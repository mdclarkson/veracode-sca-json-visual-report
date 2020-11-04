import json

global vsum
global lsum
vulns={}
vsum={}
lsum={}
libs={}
versions=[]
vulnlist=[]

'''
########################
# DATA SCHEMA
########################
records
	metadata
	graphs
	libraries
	vulnerabilities
	unmatchedLibraries
	vulnMethods
########################


#####
##### Vulnerabilities
#####

    "vulnerabilities" : [ {
      "disclosureDate" : "2014-09-04T16:00:00.000+0000",
      "cve" : "2014-6394",
      "title" : "Elevation Of Privileges",
      "overview" : "send before 0.8.4 for Node.js uses a partial comparison for verifying whether a directory is within the document root, which allows remote attackers to access restricted directories, as demonstrated using 'public-restricted' under a 'public' directory.",
      "language" : "JS",
      "vulnerabilityTypes" : [ "Authorization (Access Control)", "File I/O" ],
      "cvssScore" : 7.5,
      "libraries" : [ {
        "details" : [ {
          "updateToVersion" : "0.8.4",
          "versionRange" : "0.0.0-0.8.3",
          "fixText" : "",
          "patch" : "https://github.com/pillarjs/send/commit/9c6ca9b2c0b880afd3ff91ce0d211213c5fa5f9a"
        } ],
        "_links" : {
          "ref" : "/records/0/libraries/138/versions/2"
        }
      } ],
      "_links" : {
        "html" : "https://www.sourceclear.com/vulnerability-database/vulnerabilities/1316"
      },
      "hasExploits" : false
    }, {

#####
##### Libraries
#####

    "libraries": [
        {
            "name": "accept",
            "description": "HTTP Accept-* headers parsing",
            "author": null,
            "authorUrl": null,
            "language": "JS",
            "coordinateType": "NPM",
            "coordinate1": "accept",
            "coordinate2": "",
            "bugTrackerUrl": "https://github.com/hapijs/accept/issues",
            "codeRepoType": "GIT",
            "codeRepoUrl": "git://github.com/hapijs/accept.git",
            "latestRelease": "1.0.0",
            "latestReleaseDate": "2014-10-03T23:26:22.000+0000",
            "versions": [
                {
                    "version": "1.0.0",
                    "releaseDate": "2014-10-03T23:26:22.000+0000",
                    "sha1": "83ef883968b85a40c5011604282a220ff01e62ad",
                    "sha2": "c2cf79aaa2ff1c772b5ef66500a0dbf1d238ab1238deaa61c7a885f337d9385b",
                    "bytecodeHash": null,
                    "platform": "",
                    "licenses": [
                        {
                            "name": "BSD3",
                            "license": "BSD 3-Clause \"New\" or \"Revised\" License (BSD-3-Clause)",
                            "fromParentPom": false
                        }
                    ],
                    "_links": {
                        "html": "https://www.sourceclear.com/vulnerability-database/libraries/8714?version=1.0.0"
                    }
                }
            ],
            "_links": {
                "html": "https://www.sourceclear.com/vulnerability-database/libraries/871"
            }
        },
#####
##### Vulnerable Methods
#####
    "vulnMethods" : [ {
      "calls" : [ {
        "method" : {
          "className" : "SessionRedirectMixin",
          "descriptor" : null,
          "id" : null,
          "methodName" : "resolve_redirects",
          "moduleName" : ".requests.sessions"
        },
        "callChains" : [ [ {
          "callee" : {
            "className" : "SessionRedirectMixin",
            "descriptor" : null,
            "id" : null,
            "methodName" : "resolve_redirects",
            "moduleName" : ".requests.sessions"
          },
          "caller" : {
            "className" : null,
            "descriptor" : null,
            "id" : null,
            "methodName" : null,
            "moduleName" : ".main"
          },
          "fileName" : "main.py",
          "internal" : true,
          "lineNumber" : 10
        } ] ]
      } ],
      "links" : [ {
        "ref" : "/records/0/libraries/6/versions/0"
      } ]
    }, 

'''


def getJSONdata():
	#
	# Importing JSON data
	#
	with open('sca.json') as json_file:
		data = json.load(json_file)
		#data2 = json.dumps(data, indent=4)
		#print(data2)
		scadata = data["records"]	
		vulncount=0
		libcount=0
		vmscount=0
		for rec in scadata:
			global reporturl
			reporturl = rec['metadata']['report']
			#print("expecteed vulns: ", len(rec['vulnerabilities']))
			for v in rec['vulnerabilities']:
				title = v['title']
				if v["cve"] is None:
					cve = "Premium Data"
				else:
					cve = v["cve"]
				overview = v["overview"].encode()
				language = v["language"]
				cvssscore = v["cvssScore"]
				if cvssscore >= 7:
					severity = "high"
				elif cvssscore < 7 and cvssscore >= 4:
					severity = "medium"
				else:
					severity = "low"	
				href = v["_links"]["html"]
				for vl in v["libraries"]:
					for d in vl["details"]:
						updatetoversion=d["updateToVersion"]
						versionrange=d["versionRange"]
						fixtext=d["fixText"]
						patch=d["patch"]
					vlhref=vl["_links"]["ref"]
				vulns[vulncount]={'title' : title, 'overview' : overview, 'language' : language, 'cve' : cve, 'cvssscore' : cvssscore, 'severity' : severity, 'href' : href, 'updatetoversion' : updatetoversion, 'versionrange' : versionrange, 'fixtext' : fixtext, 'patch' : patch, 'vlhref' : vlhref }
				if updatetoversion is None:
					fix = " "
				else:
					fix = "Please update to version " + str(updatetoversion) + "."
				vulnlist.append([str(cve), str(severity), str(cvssscore), str(title), str(overview), str(fix)])
				vulncount = vulncount + 1
			for l in rec['libraries']:
				name = l['name']
				description = l['description']
				packagemanager = l['coordinateType']
				latestrelease = l['latestRelease']
				latestreleasedate = ['latestReleaseDate']
				href = l['_links']['html']
				for ver in l["versions"]:
					version = ver["version"]
					releasedate = ver["releaseDate"]
					versions.append(version+" ("+releasedate+")")
				if str(latestrelease) not in versions:
					outofdate="true"
				else:
					outofdate="false"
				libs[libcount]={'name' : name, 'description' : description, 'packagemanager' : packagemanager, 'latestreleasedate' : latestreleasedate, 'href' : href, 'versions' : versions, 'outofdate' : outofdate}
				libcount = libcount + 1
				global vulnmethodstotal
				vulnmethodstotal = len(rec['vulnMethods'])	


def vulnsummary(sev):
	#
	# Capture Vulnerability Totals
	#
	high=0
	medium=0
	low=0
	for k, v in vulns.items():
		if vulns[k]['severity'] == "high":
			high=high+1	
		elif vulns[k]['severity'] == "medium":
			medium=medium+1
		elif vulns[k]['severity'] == "low":
			low=low+1
		else:
			high=0
			medium=0
			low=0
	total = high+medium+low
	vsum={'high' : high, 'medium' : medium, 'low' : low, 'total' : total}
	return vsum[sev]

def getVulns(severity):
	for k, v in vulns.items():
		if str(severity) in vulns[k]['severity']:
			print(vulns[k]) 

def getLibs(x):
	for k, v in libs.items():
		if str(x) in libs[k]['outofdate']:
			print(libs[k])

def getVulnTable():
	vlistcounter=0
	vlistotal=len(vulnlist)
	s=""
	for x in vulnlist:
		if vlistcounter < (vlistotal-1):
			#s+="[\""+ x[0] +"\", \""+ x[1] +"\", \""+ x[2] +"\", \""+ x[3] +"\", \""+ x[4] +"\", \""+ x[5] +"\"], "
			s+="[\""+ x[0] +"\", \""+ x[1] +"\", \""+ x[2] +"\", \""+ x[3] +"\", \""+ x[5] +"\"], "
		else:
			#s+="[\""+ x[0] +"\", \""+ x[1] +"\", \""+ x[2] +"\", \""+ x[3] +"\", \""+ x[4] +"\", \""+ x[5] +"\"]"
			s+="[\""+ x[0] +"\", \""+ x[1] +"\", \""+ x[2] +"\", \""+ x[3] +"\", \""+ x[5] +"\"]"
		vlistcounter=vlistcounter+1
	return s

def libssummary(x):
	#
	# Capture Vulnerability Totals
	#
	t=0
	f=0
	for k, v in libs.items():
		if libs[k]['outofdate'] == "true":
			t=t+1	
		elif libs[k]['outofdate'] == "false":
			f=f+1
		else:
			t=0
			f=0
	total = t+f
	lsum={'true' : t, 'false' : f, 'total' : total}
	return lsum[x]


def writeHTML():
	f = open("sca-report.html", "w")
	html1 = """<html>
		<head>
			<script src="https://unpkg.com/gridjs/dist/gridjs.production.min.js"></script>
			<link href="https://unpkg.com/gridjs/dist/theme/mermaid.min.css" rel="stylesheet" />
			<script type="module">import{Grid,html}from"https://unpkg.com/gridjs/dist/gridjs.production.es.min.js";</script>
			<script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
		    <script type="text/javascript">
		      google.charts.load('current', {'packages':['corechart']});
		      google.charts.setOnLoadCallback(drawChart);
		      function drawChart() {
		        var data = google.visualization.arrayToDataTable([
		          ['Severity', 'Count'],
		          ['High',    """+str(vulnsummary('high'))+"""],
		          ['Medium',     """+str(vulnsummary('medium'))+"""],
		          ['Low',  """+str(vulnsummary('low'))+"""]
		        ]);
		        var options = {
		          slices: [{color: '#FF0000'}, {color: '#FF8C00'}, {color: '#8fbc48'}],
		          legend: {textStyle: {color: 'white'}},
		          backgroundColor: '#000000'
		        }
		        var chart = new google.visualization.PieChart(document.getElementById('piechart'));
		        chart.draw(data, options);
		      }
		    </script>
		    <style type="text/css">
		      html, body{font-family: Arial, Helvetica, sans-serif;}
		      h2{font-size: 1.5em; text-align: center;}
		      .header{height: 100px;}
		      button{border:none;}
		      .logo{width:300px; float: left;}
		      .report{max-width:800px; float: right;}
		      .report button{width:100px; padding:14px; border:none; border-radius: 25px;}
		      .report button a{color:#fff; text-decoration: none; font-weight: bold;}
		      .pink{background-color: #d73185;}
		      .column {float: left;}
		      .column h5{margin: 0 auto; text-align: center; font-weight: bold; font-size:7.5em;}
		      .column h6{margin: 0 auto; text-align: center; font-variant: small-caps;}
		      .row:after {content: ""; display: table; clear: both;}
		      .left{max-width:500px; width:50%;}
		      .left h2{color: #fff;}
		      .middle{max-width: 300px; height: 300px; width:25%; background-color:#e2e369;}
		      .right{max-width: 300px; height: 300px; width:25%; background-color: #37a2e4;}
		      #wrapper{width:100%; position: absolute;}
		      #container{max-width:1200px; min-height:1100px; margin: 0 auto;}
		      .row{width:100%; display: block; min-width:1100px;}
		      .chartruce{background-color: #e2e369;}
		      html,body{background-color:#000;}
		    </style>    
		  </head>
		  <body>
		    <div id="wrapper">
		      <div id="container">
		        <div class="row header">
		          <div class="logo">
		            <img src="https://community.veracode.com/resource/1544728435000/VeracodeCommunityLogo" alt="Home" width="250">
		          </div>
		          <div class="report"><button class="pink"><a href=\""""+str(reporturl)+"""\" target="_blank">Full Report</a></button></div>
		        </div>
		        <div class="row">
		          <div class="left column">
		            <h2>SCA VULNERABILITIES</h2>
		            <div id="piechart" style="width: 500px; height: 300px;"></div>
		          </div>
		          <div class="middle column"><h2>VULN METHODS</h2><h5>"""+str(vulnmethodstotal)+"""</h5></div>
		          <div class="right column"><h2>OLD LIBRARIES</h2><h5>"""+str(libssummary('true'))+"""</h5><h6>"""+str(libssummary('false'))+""" libraries up to date</h6></div>
		        </div>
		        <div class="row">
		          <div id="gridjs"></div>
		        </div>
		      </div>
		    </div>
		    <script src="https://unpkg.com/gridjs/dist/gridjs.development.js"></script>
		    <script type="text/javascript">
		      new gridjs.Grid({
		        columns: ["CVE", "SEVERITY", "CVSS", "TITLE", "INSTRUCTIONS"],
		        search: true,
		        sort: true,
		        pagination: false,
		        data: ["""+str(getVulnTable())+"""]
		      }).render(document.getElementById("gridjs"));
		    </script>
		  </body>
		</html>
		"""
	f.write(html1)
	f.close()

def main():
	#
	getJSONdata()
	writeHTML()

main()