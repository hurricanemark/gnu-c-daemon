pipeline {
    agent { label 'linux' } 
    stages {
        stage ('Build') {
            steps {
                sh 'make all' 
            }
        }
    }
}
