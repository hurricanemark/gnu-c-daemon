pipeline {
    agent { 
        node { 
            label 'AzureSLES-13.91.130.158' 
        } 
    } 

    stages {
        stage ('Build') {
            steps {
                sh 'make all' 
            }
        }
    }
}
