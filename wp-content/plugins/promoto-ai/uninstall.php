<?php
/**
 * Uninstall Promoto AI
 * 
 * This file is executed when the plugin is uninstalled.
 * It removes all plugin data from the database.
 */

// If uninstall not called from WordPress, exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Remove plugin options
delete_option('seo_pilot_credentials');
delete_option('seo_pilot_app_passwords');
delete_option('seo_pilot_activated');
delete_option('seo_pilot_activation_time');
delete_option('seo_pilot_debug_logs');

// Remove any other plugin data if needed
// delete_option('seo_pilot_settings');
// delete_option('seo_pilot_api_key'); 