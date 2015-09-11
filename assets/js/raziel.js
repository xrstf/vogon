jQuery(function($) {
	// Sets the min-height of #page-wrapper to window size
	$(window).bind('load resize', function() {
		var topOffset = 50;
		var width     = (this.window.innerWidth > 0) ? this.window.innerWidth : this.screen.width;

		if (width < 768) {
			$('div.navbar-collapse').addClass('collapse');
			topOffset = 100; // 2-row-menu
		}
		else {
			$('div.navbar-collapse').removeClass('collapse');
		}

		var height = ((this.window.innerHeight > 0) ? this.window.innerHeight : this.screen.height) - 1;

		height = height - topOffset;
		if (height < 1) height = 1;

		if (height > topOffset) {
			$('#page-wrapper').css('min-height', height + 'px');
		}
	});

	// init Bootstrap's tooltips
	// $('[data-toggle="tooltip"]').tooltip();

	// init Select2
	$('.select2').select2();

	// init relative times
	$('time.rel').timeago();

	var consumerForm = $('#consumer-form');
	if (consumerForm.length > 0) {
		function updateAuthTypeForm() {
			var authType = $('#auth-type-toggle input:checked').val();

			$('#authentications > div').hide();
			$('#auth-' + authType).show();
		}

		$('#auth-type-toggle label').on('click', function() {
			setTimeout(updateAuthTypeForm, 0); // wait for :checked to be ready
		});

		$('.restriction .panel-heading input').on('change', function() {
			var enabled = this.checked;
			var panel   = $(this).closest('.restriction');

			panel.removeClass('panel-success panel-danger panel-default');

			if (!enabled) {
				panel.addClass('panel-default');
			}
			else {
				panel.addClass($(this).is('.failed') ? 'panel-danger' : 'panel-success');
			}
		});

		updateAuthTypeForm();
	}
});
