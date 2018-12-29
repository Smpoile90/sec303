
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

    def dbBuild(self, dbresponse):
        self.id = dbresponse[1]
        self.title = dbresponse[2]
        self.time_create =  dbresponse[3]
        self.time_change = dbresponse[4]
        self.risk_value = dbresponse[4]
        self.cve_id = dbresponse[5]
        self.time_release = dbresponse[6]

    def __str__(self):
        string = "{},{},{},{},{},{},{},{}".format(self.id,self.title,self.time_create,self.time_change,
                self.risk_value, self.risk_name, self.cve_id,self.time_release)
        return string
