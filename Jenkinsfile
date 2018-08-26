pipeline {
    agent { label 'linux' } 
    stage ('Clone Source Code')
        steps {
            git url: 'https://github.com/jfrogdev/project-examples.git'
        }
    stage ('Build')
        steps {
            sh 'make all' 
        }
}
