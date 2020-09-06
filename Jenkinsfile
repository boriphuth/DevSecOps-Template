properties ([
  parameters ([
    string(name: 'appRepoURL', value: "https://github.com/boriphuth/sample.git", description: "Application's git repository"),
	string(name: 'folderName', value: "backend", description: "Project's folder name"),
    string(name: 'dockerImage', value: "api:prod", description: "docker Image with tag"),
    string(name: 'targetURL', value: "http://production.devops", description: "Web application's URL"),
    choice(name: 'appType', choices: ['Java', 'Node', 'Angular'], description: 'Type of application'),
    string(name: 'hostMachineName', value: "production.devops", description: "Hostname of the machine"),
    string(name: 'hostMachineIP', value: "192.168.34.13", description: "Public IP of the host machine")
   // password(name: 'hostMachinePassword', value: "", description: "Password of the target machine")
    ])
])

def repoName="";
def app_type="";
def workspace="";

node {
	stage('Checkout SCM'){
		catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE'){
			checkout scm
			workspace = pwd ()
		}
    }
	stage('Init Sonarqube'){
		catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE'){
	    	sh """
                docker volume create --name sonarqube_data
                docker volume create --name sonarqube_extensions
                docker volume create --name sonarqube_logs
         	"""
	  	}
    }
    stage('pre-build setup'){
		catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE'){
	    	// sh """
            // 	docker-compose -f Anchore-Engine/docker-compose.yaml up -d
         	// """
			sh """
                docker run -d \
                -p 9000:9000 \
                -v sonarqube_extensions:/opt/sonarqube/extensions \
                sonarqube:8.4-community
         	"""  
			 timeout(5) {
                waitUntil {
                    def r = sh script: 'wget -q http://192.168.34.16:9000 -O /dev/null', returnStatus: true
                    return (r == 0);
                }
            }
            sleep(60)
	  	}
    } 
    stage('Check secrets'){
		catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE'){
    		sh """
            	rm trufflehog || true
            	docker run gesellix/trufflehog --json --regex ${appRepoURL} > trufflehog
            	cat trufflehog
            """
	    	def truffle = readFile "trufflehog"   
	    	if (truffle.length() == 0){
              echo "Good to go" 
            }
            else {
            	echo "Warning! Secrets are committed into your git repository."
	      		throw new Exception("Secrets might be committed into your git repo")
            }
	  	}
    }    
	stage('Source Composition Analysis'){
		catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE'){
	    	sh "git clone ${appRepoURL} || true" 
            repoName = sh(returnStdout: true, script: """echo \$(basename ${appRepoURL.trim()})""").trim()
            repoName = sh(returnStdout: true, script: """echo ${repoName} | sed 's/.git//g'""").trim()
	    	if (appType.equalsIgnoreCase("Java")){
	      		app_type = "pom.xml"	
	    	}
			else {
				app_type = "package.json"
				dir ("${repoName}"){
					sh "npm install"
				}
			}
        	snykSecurity failOnIssues: false, monitorProjectOnBuild: false, snykInstallation: 'Snyk', snykTokenId: 'snyk-token', targetFile: "${repoName}/${folderName}/${app_type}"
		   
			// def snykFile = readFile 'snyk_report.html'
			// if (snykFile.exists()) {
			// 	throw new Exception("Vulnerable dependencies found!")    
			// }
			// else {
			// 	echo "Please enter the app repo URL"
			// 	currentBuild.Result = "FAILURE"
			// }
	  	}
	}
	stage('SAST'){
		catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE'){
			if (appType.equalsIgnoreCase("Java")){
				withSonarQubeEnv('sonarqube'){
					dir("${repoName}/${folderName}"){
						sh "mvn clean package sonar:sonar"
					}
				}
				
				sleep(60)

				timeout(5) {
					def qg = waitForQualityGate() 
					if (qg.status != 'OK') {     
						error "Pipeline aborted due to quality gate failure: ${qg.status}"    
					}	
				}
			}
    	}
	}
	// stage("docker_scan"){
    //   sh '''
    //     docker run -d --name db arminc/clair-db
    //     sleep 15 # wait for db to come up
    //     docker run -p 6060:6060 --link db:postgres -d --name clair arminc/clair-local-scan
    //     sleep 1
    //     DOCKER_GATEWAY=$(docker network inspect bridge --format "{{range .IPAM.Config}}{{.Gateway}}{{end}}")
    //     wget -qO clair-scanner https://github.com/arminc/clair-scanner/releases/download/v8/clair-scanner_linux_amd64 && chmod +x clair-scanner
    //     ./clair-scanner --ip="$DOCKER_GATEWAY" myapp:latest || exit 0
    //   '''
    // }
	stage('Container Image Scan'){
    	catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE'){
	    	sh "rm anchore_images || true"
            sh """ echo "$dockerImage" > anchore_images"""
            anchore 'anchore_images'
	  	}
    }
	stage('DAST'){
    	catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE'){
			sh """
			rm -rf Archerysec-ZeD/zap_result/owasp_report || true
			docker run -v `pwd`/Archerysec-ZeD/:/zap/wrk/:rw -t owasp/zap2docker-stable zap-baseline.py \
				-t ${targetURL} -J owasp_report
			"""
        }
	}
	stage('Inspec'){
  		catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE'){
			/*to install inspec as a package
			curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec*/
			sh """
				rm inspec_results || true
				inspec exec Inspec/hardening-test -b ssh --host=${hostMachineIP} --user=${hostMachineName} -i ~/.ssh/id_rsa --reporter json:./inspec_results
				cat inspec_results | jq
			"""
	  	}	
	}
	stage('Clean up'){
		catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE'){
        	sh """
				rm -r ${repoName} || true
				mkdir -p reports/trufflehog
				mkdir -p reports/snyk
				mkdir -p reports/Anchore-Engine
				mkdir -p reports/OWASP
				mkdir -p reports/Inspec
            	mv trufflehog reports/trufflehog || true
				mv *.json *.html reports/snyk || true
				cp -r /var/lib/jenkins/jobs/${JOB_NAME}/builds/${BUILD_NUMBER}/archive/Anchore*/*.json ./reports/Anchore-Engine ||  true
				mv inspec_results reports/Inspec || true
            """
			//cp Archerysec-ZeD/owasp_report reports/OWASP/ || ture	    
			sh """
				docker system prune -f
				docker-compose -f Sonarqube/sonar.yml down
				docker-compose -f Anchore-Engine/docker-compose.yaml down -v
			"""
	  	}
    }
}