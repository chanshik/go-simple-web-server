package server

import (
	"bufio"
	"fmt"
	auth "github.com/abbot/go-http-auth"
	"github.com/dustin/go-humanize"
	"github.com/kr/fs"
	"gopkg.in/fsnotify.v1"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"regexp"
)

type MethodParam struct {
	Out http.ResponseWriter
	Req *http.Request
	Resp *Response
	Tpl *template.Template
	Vars map[string]interface{}
}

type Method struct {
	Handler     func(param *MethodParam)
	Template    string
	UseRegexUrl bool
	RegexUrl    string
}

type UrlHandler struct {
	GET           Method
	POST          Method
	PUT           Method
	DELETE        Method
	HEAD          Method
	UseDigestAuth bool
}

type DigestAuthInfo struct {
	Realm    string
	Username string
	Password string
}

type WebServerConfig struct {
	DigestFilename string
	Realm          string
	Port           int
	VerboseLog     bool
	IsDebug        bool
}

type WebServer struct {
	config          *WebServerConfig
	errorChan       chan error
	watcherDoneChan chan bool

	authAccounts map[string]string
	httpAuth     *auth.DigestAuth
	digestMap    map[string]DigestAuthInfo

	layoutFileMap     map[string]string                        // Layout name -> File path
	templateFileMap   map[string]string                        // Template name -> File path
	layoutTemplateMap map[string]map[string]*template.Template // Layout name -> (Template name -> *Template)

	urlMethodFuncMap map[string]map[string]Method // URL -> (Method name -> Method)
	urlHandlerExistsMap map[string]bool // URL -> exists
	regexUrlMap map[*regexp.Regexp]string  // Compiled Regex Pattern -> URL

	customFuncMap template.FuncMap

	currentLayout string

	exposedAddress string
	verboseLog     bool
}

func NewWebServer(errorChan chan error, config *WebServerConfig) *WebServer {
	server := &WebServer{}

	server.errorChan = errorChan
	server.config = config

	if config.DigestFilename != "" {
		server.httpAuth = auth.NewDigestAuthenticator(config.Realm, server.DigestCallback)
		digestMap, err := server.LoadDigestFile(config.DigestFilename)
		if err != nil {
			log.Printf("%s\n", err)
			server.digestMap = make(map[string]DigestAuthInfo)
		} else {
			server.digestMap = digestMap
		}
	}

	server.urlMethodFuncMap = make(map[string]map[string]Method)
	server.regexUrlMap = make(map[*regexp.Regexp]string)
	server.urlHandlerExistsMap = make(map[string]bool)
	server.customFuncMap = template.FuncMap{
		"comma": server.Comma,
	}

	server.exposedAddress = fmt.Sprintf("0.0.0.0:%d", config.Port)
	server.watcherDoneChan = make(chan bool)
	server.currentLayout = "default"

	return server
}

func (self *WebServer) Comma(number int) string {
	return humanize.Comma(int64(number))
}

func (self *WebServer) VerboseLog(formatString string, args ...interface{}) {
	if self.config.VerboseLog {
		if args != nil {
			log.Printf(formatString, args...)
		} else {
			log.Printf(formatString)
		}
	}
}

func (self *WebServer) LoadLayout(layoutDir string) {
	self.layoutFileMap = make(map[string]string)

	walker := fs.Walk(layoutDir)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			self.errorChan <- fmt.Errorf("LoadLayout: Failed walking directory: %s", err)
			continue
		}

		layoutFile := walker.Path()
		if strings.HasSuffix(layoutFile, ".ghtml") == false {
			continue
		}
		info, err := os.Stat(layoutFile)
		if err != nil {
			self.errorChan <- fmt.Errorf("LoadLayout: Failed open file %s: %s", layoutFile, err)
		}
		if info.IsDir() {
			continue
		}

		_, filename := path.Split(layoutFile)
		nameOnly := strings.Split(filename, ".ghtml")[0]
		self.layoutFileMap[nameOnly] = layoutFile

		self.VerboseLog("Loading layout '%s'\n", nameOnly)
	}
}

func (self *WebServer) LoadAsset(layoutDir, templateDir string) {
	self.LoadLayout(layoutDir)

	self.templateFileMap = make(map[string]string)

	walker := fs.Walk(templateDir)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			self.errorChan <- fmt.Errorf("LoadAsset: Failed open %s: %s", walker.Path(), err)
			continue
		}

		templateFile := walker.Path()
		info, err := os.Stat(templateFile)
		if err != nil {
			self.errorChan <- fmt.Errorf("LoadAsset: Failed open %s: %s", walker.Path(), err)
			continue
		}
		if info.IsDir() == true {
			continue
		}

		_, filename := path.Split(templateFile)
		nameOnly := strings.Split(filename, ".ghtml")[0]

		self.templateFileMap[nameOnly] = templateFile
	}

	self.layoutTemplateMap = self.BuildTemplate(self.layoutFileMap, self.templateFileMap)
}

// Build template.Template using all layout with each template file.
func (self *WebServer) BuildTemplate(
	layoutFileMap, templateFileMap map[string]string) map[string]map[string]*template.Template {

	layoutTemplateMap := make(map[string]map[string]*template.Template)

	for layoutName, layoutFile := range layoutFileMap {
		layoutTemplateMap[layoutName] = make(map[string]*template.Template)

		for templateName, templateFile := range templateFileMap {
			parsedTemplate := template.Must(template.New("template").Funcs(self.customFuncMap).ParseFiles(layoutFile, templateFile))

			self.VerboseLog("Building template '%s:%s'\n", layoutName, templateName)
			layoutTemplateMap[layoutName][templateName] = parsedTemplate
		}
	}

	return layoutTemplateMap
}

func (self *WebServer) RunReloadHandler(layoutDir, templateDir string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		self.errorChan <- fmt.Errorf("Failed setup Reloader: %s", err)
		return
	}
	defer watcher.Close()

	watcher.Add(layoutDir)
	watcher.Add(templateDir)

	for {
		select {
		case event := <-watcher.Events:
			if strings.HasSuffix(event.Name, "ghtml") == false {
				continue
			}

			log.Printf("Asset changed. Reloading all assets: %s", event)
			self.LoadAsset(layoutDir, templateDir)

		case err := <-watcher.Errors:
			log.Printf("Asset changed. But, failed reloading: %s", err)
			panic(err.Error())
		}
	}
}

type Response struct {
	Data map[string]interface{}
}

func (self *WebServer) findRegexUrlMatch(targetUrl string) (string, *map[string]interface{}) {
	for urlPattern, realUrl := range self.regexUrlMap {
		matched := urlPattern.FindStringSubmatch(targetUrl)
		if len(matched) == 0 {
			continue
		}

		varNames := urlPattern.SubexpNames()  // varNames has 1 more elements than matched.
		vars := make(map[string]interface{})
		for idx, varName := range varNames {
			if varName == "" {
				continue
			}

			vars[varName] = matched[idx]
		}

		return realUrl, &vars
	}

	return "", nil
}

func (self *WebServer) stubHandler(w http.ResponseWriter, r *http.Request) {
	var methodHandlerMap map[string]Method
	var exists bool
	var methodVars *map[string]interface{} = nil

	methodHandlerMap, exists = self.urlMethodFuncMap[r.URL.Path]
	if exists == false {
		realUrl, vars := self.findRegexUrlMatch(r.URL.Path)
		if realUrl == "" {
			http.NotFound(w, r)
			return
		}

		methodHandlerMap, exists = self.urlMethodFuncMap[realUrl]
		if exists == false {
			http.NotFound(w, r)
			return
		}

		methodVars = vars
	}

	method, exists := methodHandlerMap[r.Method]
	if exists == false {
		http.NotFound(w, r)
		return
	}

	r.ParseForm()
	w.Header().Set("Content-Type", "text/html")

	var template *template.Template
	if method.Template != "" {
		template = self.Template(method.Template)
	}
	response := Response{
		Data: make(map[string]interface{}),
	}

	param := MethodParam{
		Out: w,
		Req: r,
		Resp: &response,
		Tpl: template,
		Vars: *methodVars,
	}
	method.Handler(&param)
}

func (self *WebServer) AddHandler(url string, urlHandler UrlHandler) {
	useRegexUrl := true
	matchUrl := url

	urlPrefix := self.ExtractUrlPrefix(url)
	if urlPrefix == url && url != "/" {
		useRegexUrl = false
	} else {
		matchUrl = "/"
	}
	self.urlMethodFuncMap[url] = make(map[string]Method)

	handlers := []Method{
		urlHandler.GET, urlHandler.POST, urlHandler.PUT,
		urlHandler.DELETE, urlHandler.HEAD,
	}
	methodNames := []string{
		"GET", "POST", "PUT", "DELETE", "HEAD",
	}

	for idx, handler := range handlers {
		if handler.Handler != nil {
			self.urlMethodFuncMap[url][methodNames[idx]] = handler
			handler.UseRegexUrl = useRegexUrl

			if useRegexUrl {
				handler.RegexUrl = self.TransformUrlToRegex(url)
				self.regexUrlMap[regexp.MustCompile(handler.RegexUrl)] = url
			}
		}
	}

	_, exists := self.urlHandlerExistsMap[matchUrl]
	if exists == false {
		self.urlHandlerExistsMap[matchUrl] = true

		if urlHandler.UseDigestAuth {
			http.HandleFunc(matchUrl, auth.JustCheck(self.httpAuth, self.stubHandler))
		} else {
			http.HandleFunc(matchUrl, self.stubHandler)
		}
	}
}

func Log(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("HTTP: %s %s %s", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}

func (self *WebServer) Layout(layoutName string) error {
	_, exists := self.layoutTemplateMap[layoutName]
	if exists == false {
		return fmt.Errorf("Failed load layout %s", layoutName)
	}

	self.currentLayout = layoutName
	return nil
}

func (self *WebServer) Template(templateName string) *template.Template {
	templateMap, exists := self.layoutTemplateMap[self.currentLayout]
	if exists == false {
		panic(fmt.Errorf("Failed load layout %s", self.currentLayout))
	}

	parsedTemplate, exists := templateMap[templateName]
	if exists == false {
		panic(fmt.Errorf("Failed load template %s", templateName))
	}

	return parsedTemplate
}

func (self *WebServer) MaxAgeHandler(seconds int, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", fmt.Sprintf("max-age=%d, public, must-revalidate, proxy-revalidate", seconds))
		h.ServeHTTP(w, r)
	})
}
func (self *WebServer) PublicHandler(publicDir string) {
	fileServer := http.FileServer(http.Dir(publicDir))

	if self.config.IsDebug {
		http.Handle("/public/", http.StripPrefix("/public/", self.MaxAgeHandler(0, fileServer)))
	} else {
		http.Handle("/public/", http.StripPrefix("/public/", fileServer))
	}
}

// Load digest file and parse line by line.
// Return: "username:realm" -> {username, password, realm}
func (self *WebServer) LoadDigestFile(filename string) (map[string]DigestAuthInfo, error) {
	fullPath := filename
	if !strings.HasPrefix(filename, "/") {
		programDir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
		fullPath = programDir + "/" + filename
	}
	f, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("Failed open digest file: %s\n", filename)
	}

	defer f.Close()

	reader := bufio.NewReader(f)
	digestMap := make(map[string]DigestAuthInfo)

	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			if line[0] == '#' {
				continue
			}

			// Each line has a "username:realm:password" formatted user account information.
			items := strings.Split(strings.TrimSpace(line), ":")
			if len(items) != 3 {
				continue
			}

			self.VerboseLog("DigestAuth user registed: %s\n", items[0])
			authInfo := DigestAuthInfo{
				Username: items[0],
				Realm:    items[1],
				Password: items[2],
			}

			digestKey := fmt.Sprintf("%s:%s", items[0], items[1])
			digestMap[digestKey] = authInfo
		}

		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
	}

	return digestMap, nil
}

func (self *WebServer) DigestCallback(username, realm string) string {
	digestKey := fmt.Sprintf("%s:%s", username, realm)
	authInfo, exists := self.digestMap[digestKey]

	self.VerboseLog("DigestAuth requested: %s\n", username)

	password := ""
	if exists == false {
		self.VerboseLog("DigestAuth user not found: %s\n", username)
		password = ""
	} else {
		password = authInfo.Password
	}

	return password
}

func (self *WebServer) ExtractUrlPrefix(url string) string {
	for idx, ch := range url {
		if ch == '{' {
			return url[:idx]
		}
	}

	return url
}

func (self *WebServer) TransformUrlToRegex(url string) string {
	baseIdx := 0
	startIdx := 0
	endIdx := 0

	mappingRuleMap := map[string]string{
		"int": `\d+`,
		"str": `.+`,
	}
	regResult := ""

	if url == "/" {
		return "^/$"
	}

	for {
		if baseIdx >= len(url) {
			break
		}

		startIdx = strings.Index(url[baseIdx:], "{")
		if startIdx == -1 {
			break
		}

		endIdx = strings.Index(url[baseIdx+startIdx:], "}")
		if endIdx == -1 {
			break
		}
		endIdx = startIdx + endIdx + 1

		regResult += url[baseIdx : baseIdx+startIdx]
		subMatch := url[baseIdx+startIdx+1 : baseIdx+endIdx-1]

		keyAndType := strings.Split(subMatch, ":")
		keyType := "str"
		if len(keyAndType) == 2 {
			keyType = keyAndType[1]
		}

		regPattern := fmt.Sprintf("(?P<%s>%s)", keyAndType[0], mappingRuleMap[keyType])
		regResult += regPattern

		baseIdx = baseIdx + endIdx
		startIdx = 0
		endIdx = 0
	}

	return regResult
}

func (self *WebServer) Run() {
	if self.config.IsDebug {
		log.Println("Run ReloadHandler")
		go self.RunReloadHandler("layout", "templates")
	}

	var err error
	if self.config.VerboseLog {
		err = http.ListenAndServe(self.exposedAddress, Log(http.DefaultServeMux))
	} else {
		err = http.ListenAndServe(self.exposedAddress, nil)
	}
	if err != nil {
		self.errorChan <- fmt.Errorf("Failed start WebServer: %s", err)
	}
}
