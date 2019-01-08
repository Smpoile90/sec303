
class Vuln:
    def vulDBbuild(self,response):
        self.id = response["entry"]["id"]
        self.title = response["entry"]["title"]
        self.time_create =  response["entry"]["timestamp"]["create"]
        self.time_change = response["entry"]["timestamp"]["change"]
        self.risk_value = response["vulnerability"]["risk"]["value"]
        self.risk_name = response["vulnerability"]["risk"]["name"]
        self.cve_id = response["source"]["cve"]["id"]
        self.time_release = response["advisory"]["date"]
        #self.description = 'None'

    def dbBuild(self, dbresponse):
        self.id = dbresponse[1]
        self.title = dbresponse[2]
        self.time_create =  dbresponse[3]
        self.time_change = dbresponse[4]
        self.risk_value = dbresponse[4]
        self.cve_id = dbresponse[5]
        self.time_release = dbresponse[6]
        #self.description = dbresponse[7]

    def vulnersBuild(self,vulnersDict):
        self.id = vulnersDict['id']
        self.title = vulnersDict['title']
        self.time_create =  vulnersDict['published']
        self.time_change = vulnersDict['modified']
        self.risk_value = vulnersDict['cvss']['score']
        self.risk_name = vulnersDict['cvss']['vector']
        self.cve_id = vulnersDict['type']
        self.time_release = self.time_create #DOESNT EXIST IN VULNERS
        #self.description = vulnersDict['description']

    def _default(self):
        d = {}
        d['id'] = self.id
        d['title'] = self.title
        d['time_create'] = self.time_create
        d['time_change'] = self.time_change
        d['risk_value'] = self.risk_value
        d['risk_name'] = self.risk_name
        d['cve_id'] = self.cve_id
        d['time_release'] = self.time_release
        return d

    def __str__(self):
        string = "Vulners VulnID: {} Title: {} \nTime of Creation: {} Time Updated: {}\nRisk(CVSS): {} Risk: {}\nCVE_ID or Source: {} Time of Release: {}\n"\
            .format(self.id,self.title,self.time_create,self.time_change,
                self.risk_value, self.risk_name, self.cve_id,self.time_release)
        return string
