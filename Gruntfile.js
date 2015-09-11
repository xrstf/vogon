module.exports = function (grunt) {
	grunt.initConfig({
		clean: {
			www: ['www']
		},

		copy: {
			font_awesome: {
				expand: true,
				cwd: 'assets/vendor/font-awesome',
				src: [
					'css/font-awesome.min.css',
					'fonts/*'
				],
				dest: 'www'
			},
			bootstrap: {
				expand: true,
				cwd: 'assets/vendor/bootstrap/dist',
				src: [
					'css/bootstrap.min.css',
					'fonts/*',
					'js/bootstrap.min.js',
				],
				dest: 'www'
			},
			jquery: {
				expand: true,
				cwd: 'assets/vendor/jquery/dist',
				src: 'jquery.min.js',
				dest: 'www/js'
			},
			sb_admin: {
				expand: true,
				cwd: 'assets/vendor/sb-admin-2/dist',
				src: [
					'css/sb-admin-2.css',
				],
				dest: 'www'
			},
			bootstrap_toggle: {
				expand: true,
				cwd: 'assets/vendor/bootstrap-toggle',
				src: [
					'css/bootstrap-toggle.min.css',
					'js/bootstrap-toggle.min.js',
				],
				dest: 'www'
			},
			select2: {
				expand: true,
				cwd: 'assets/vendor/select2/dist',
				src: [
					'css/select2.min.css',
					'js/select2.min.js',
				],
				dest: 'www'
			},
			timeago: {
				expand: true,
				cwd: 'assets/vendor/timeago',
				src: [
					'jquery.timeago.js',
				],
				dest: 'www/js'
			},
			raziel: {
				expand: true,
				cwd: 'assets',
				src: [
					'js/raziel.js',
				],
				dest: 'www'
			}
		}
	});

	grunt.loadNpmTasks('grunt-contrib-clean');
	grunt.loadNpmTasks('grunt-contrib-copy');

	grunt.registerTask('default', ['clean', 'copy']);
};
