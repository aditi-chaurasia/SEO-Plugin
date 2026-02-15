jQuery(document).ready(function($) {
    
    $('#seo-pilot-connect-form').on('submit', function(e) {
        e.preventDefault();
        
        var $form = $(this);
        var $btn = $('#seo-pilot-connect-btn');
        var $btnText = $btn.find('.btn-text');
        var $btnLoading = $btn.find('.btn-loading');
        var $status = $('#seo-pilot-status');
        
        // Show loading state
        $btn.prop('disabled', true);
        $btnText.hide();
        $btnLoading.show();
        $status.hide();
        
        // Make AJAX request
        $.ajax({
            url: seoPilotAjax.ajaxurl,
            type: 'POST',
            data: {
                action: 'seo_pilot_connect',
                nonce: seoPilotAjax.nonce
            },
            success: function(response) {
                if (response.success) {
                    showStatus(response.data.message || 'Verified successfully.', 'success');
                } else {
                    showStatus(response.data || 'Verification failed. Please try again.', 'error');
                }
                resetButton();
            },
            error: function(xhr, status, error) {
                showStatus('Verification failed. Please try again.', 'error');
                resetButton();
            }
        });
    });
    
    function showStatus(message, type) {
        var $status = $('#seo-pilot-status');
        $status.removeClass('seo-pilot-success seo-pilot-error')
               .addClass('seo-pilot-' + type)
               .html(message)
               .show();
    }
    
    function resetButton() {
        var $btn = $('#seo-pilot-connect-btn');
        var $btnText = $btn.find('.btn-text');
        var $btnLoading = $btn.find('.btn-loading');
        
        $btn.prop('disabled', false);
        $btnText.show();
        $btnLoading.hide();
    }
});  