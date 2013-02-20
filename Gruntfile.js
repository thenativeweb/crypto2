'use strict';

module.exports = function (grunt) {
  grunt.initConfig({
    jshint: {
      files: ['Gruntfile.js', 'lib/**/*.js', 'test/**/*.js'],
      options: {
        jshintrc: 'jshint.json'
      }
    },

    mochaTest: {
      files: ['test/**/*.js']
    },

    mochaTestConfig: {
      options: {
        reporter: 'spec',
        ui: 'tdd'
      }
    }
  });

  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-mocha-test');

  grunt.registerTask('default', [ 'jshint', 'mochaTest' ]);
};