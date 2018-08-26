pipeline {
    agent { 
        node { 
            label 'linux' 
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
