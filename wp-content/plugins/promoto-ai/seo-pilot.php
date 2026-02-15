<?php
/**
 * Plugin Name: Promoto AI
 * Description: Connect your WordPress site to Promoto AI for advanced SEO management
 * Version: 1.0.0
 * Author: AST Consulting
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: promoto-ai
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class SEOPilot {
    
    private $secret = "436578ghjhkl";
    
    public function __construct() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_scripts'));
        add_action('wp_ajax_seo_pilot_connect', array($this, 'handle_connect'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('init', array($this, 'maybe_wire_url_optimization'));
        add_action('update_option_seo_pilot_strip_category_base', array($this, 'on_strip_category_base_changed'), 10, 2);
        add_action('update_option_seo_pilot_strip_tag_base', array($this, 'on_strip_tag_base_changed'), 10, 2);
        
        // Plugin installation and activation hooks
        register_activation_hook(__FILE__, array($this, 'plugin_activated'));
        add_action('plugins_loaded', array($this, 'check_compatibility'));
        
        // Ensure Wordfence configuration runs on every load - use multiple hooks for reliability
        add_action('wp_loaded', array($this, 'ensure_wordfence_configuration'));
        add_action('admin_init', array($this, 'ensure_wordfence_configuration'));
        add_action('init', array($this, 'ensure_wordfence_configuration'));
        

    }
    
    public function add_admin_menu() {
        add_menu_page(
            'Promoto AI',
            'Promoto AI',
            'manage_options',
            'seo-pilot',
            array($this, 'admin_page'),
            'dashicons-chart-area',
            30
        );
        add_submenu_page(
            'seo-pilot',
            'URL Optimization',
            'URL Optimization',
            'manage_options',
            'seo-pilot-url-optimization',
            array($this, 'url_optimization_page')
        );
    }
    
    public function enqueue_scripts($hook) {
        if ($hook != 'toplevel_page_seo-pilot' && $hook != 'seo-pilot_page_seo-pilot-url-optimization') {
            return;
        }
        
        wp_enqueue_script('seo-pilot-admin', plugin_dir_url(__FILE__) . 'js/admin.js', array('jquery'), '1.0.0', true);
        wp_enqueue_style('seo-pilot-admin', plugin_dir_url(__FILE__) . 'css/admin.css', array(), '1.0.0');
        wp_localize_script('seo-pilot-admin', 'seoPilotAjax', array(
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('seo_pilot_nonce')
        ));
    }
    
    public function register_settings() {
        register_setting('seo_pilot_url_optimization', 'seo_pilot_strip_category_base', array(
            'type' => 'boolean',
            'sanitize_callback' => function($val){ return (bool)$val; },
            'default' => false,
        ));
        register_setting('seo_pilot_url_optimization', 'seo_pilot_strip_tag_base', array(
            'type' => 'boolean',
            'sanitize_callback' => function($val){ return (bool)$val; },
            'default' => false,
        ));
    }
    
    /**
     * Runs on every request to attach feature hooks when enabled.
     */
    public function maybe_wire_url_optimization() {
        if (get_option('seo_pilot_strip_category_base')) {
            $this->enable_strip_category_base();
            add_filter('category_link', array($this, 'filter_category_link'), 10, 2);
        }
        if (get_option('seo_pilot_strip_tag_base')) {
            $this->enable_strip_tag_base();
            add_filter('tag_link', array($this, 'filter_tag_link'), 10, 2);
            add_filter('request', array($this, 'map_tag_request_without_base'), 9);
        }
        // Inject rules dynamically so manual flushing isn't required for new terms
        if (get_option('seo_pilot_strip_category_base') || get_option('seo_pilot_strip_tag_base')) {
            add_filter('rewrite_rules_array', array($this, 'inject_rewrite_rules'));
        }
    }
    
    public function on_strip_category_base_changed($old_value, $value) {
        flush_rewrite_rules();
    }
    
    public function on_strip_tag_base_changed($old_value, $value) {
        flush_rewrite_rules();
    }
    
    public function admin_page() {
        ?>
        <div class="wrap">
            <h1>Promoto AI</h1>
            <div class="seo-pilot-container">
                <div class="seo-pilot-card">
                    <h2>Connect to Promoto AI</h2>
                    <p>Verify your WordPress connection with Promoto AI.</p>
                    
                    <form id="seo-pilot-connect-form">
                        <p class="submit">
                            <button type="submit" class="button button-primary" id="seo-pilot-connect-btn">
                                <span class="btn-text">Verify with Promoto AI</span>
                                <span class="btn-loading" style="display: none;">
                                    <span class="spinner"></span> Verifying...
                                </span>
                            </button>
                        </p>
                    </form>
                    
                    <div id="seo-pilot-status" style="display: none;"></div>
                </div>
            </div>
        </div>
        <?php
    }
    
    public function url_optimization_page() {
        $category_enabled = (bool) get_option('seo_pilot_strip_category_base');
        $tag_enabled = (bool) get_option('seo_pilot_strip_tag_base');
        ?>
        <div class="wrap">
            <h1>URL Optimization</h1>
            <form method="post" action="options.php">
                <?php settings_fields('seo_pilot_url_optimization'); ?>
                <table class="form-table" role="presentation">
                    <tbody>
                        <tr>
                            <th scope="row">Strip Category Base</th>
                            <td>
                                <label for="seo_pilot_strip_category_base" style="display:inline-flex;align-items:center;gap:10px;">
                                    <input type="checkbox" id="seo_pilot_strip_category_base" name="seo_pilot_strip_category_base" value="1" <?php checked($category_enabled, true); ?> />
                                    <span>Remove /category/ from category URLs</span>
                                </label>
                                <p class="description">When enabled, category links become example.com/news/ instead of example.com/category/news/. Rewrite rules will be refreshed.</p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">Strip Tag Base</th>
                            <td>
                                <label for="seo_pilot_strip_tag_base" style="display:inline-flex;align-items:center;gap:10px;">
                                    <input type="checkbox" id="seo_pilot_strip_tag_base" name="seo_pilot_strip_tag_base" value="1" <?php checked($tag_enabled, true); ?> />
                                    <span>Remove /tag/ from tag URLs</span>
                                </label>
                                <p class="description">When enabled, tag links become example.com/technology/ instead of example.com/tag/technology/. Rewrite rules will be refreshed.</p>
                            </td>
                        </tr>
                    </tbody>
                </table>
                <?php submit_button('Save Changes'); ?>
            </form>
        </div>
        <style>
        /* Simple toggle style enhancing default checkbox */
        #seo_pilot_strip_category_base,
        #seo_pilot_strip_tag_base {
            width: 46px; height: 24px; -webkit-appearance:none; appearance:none; background:#ccd0d4; border-radius:999px; position:relative; outline:none; cursor:pointer; transition:background .2s ease;
        }
        #seo_pilot_strip_category_base:checked,
        #seo_pilot_strip_tag_base:checked { background:#4ab866; }
        #seo_pilot_strip_category_base:before,
        #seo_pilot_strip_tag_base:before { content:""; position:absolute; top:3px; left:3px; width:18px; height:18px; background:#fff; border-radius:50%; transition:left .2s ease; }
        #seo_pilot_strip_category_base:checked:before,
        #seo_pilot_strip_tag_base:checked:before { left:25px; }
        </style>
        <?php
    }
    
    public function handle_connect() {
        // Verify nonce
        $nonce = isset($_POST['nonce']) ? sanitize_text_field( wp_unslash( $_POST['nonce'] ) ) : '';
        if ( empty($nonce) || !wp_verify_nonce($nonce, 'seo_pilot_nonce') ) {
            wp_send_json_error('Security check failed');
        }
        
        // Build full domain URL
        $site_url = get_site_url();
        $parts = wp_parse_url( $site_url );
        $scheme = isset($parts['scheme']) ? $parts['scheme'] : 'http';
        $host   = isset($parts['host']) ? $parts['host'] : '';
        $port   = isset($parts['port']) ? $parts['port'] : '';
        $domain = $host ? ($scheme . '://' . $host . ($port ? ':' . $port : '')) : $site_url;

        // Optional verification code provided from onboarding UI
        $code = '';
        
        //get current user
        $current_user = wp_get_current_user();
        if ($current_user->exists()) {
            try {
                $wordpress_username = $current_user->user_login;
                $wordpress_email = $current_user->user_email;

                // Generate app password using the new function
                $app_password = $this->generate_app_password($wordpress_username);
                
                // Create payload (no email included)
                $payload = array(
                    'domain' => $domain,
                    'username' => $wordpress_username,
                    'apppassword' => $app_password,
                );
                
                // Encode payload
                $encoded_id = $this->encrypt_payload($payload, $this->secret);
                
                // Store credentials for later use (optional)
                update_option('seo_pilot_credentials', array(
                    'username' => $wordpress_username,
                    'app_password' => $app_password,
                    'email' => $wordpress_email,
                    'domain' => $domain
                ));
                
                // Call backend verification endpoint
                $body = array('onboard' => $encoded_id);
                // No code passed from UI in simplified flow
                $response = wp_remote_post('https://promotoai.com/api/auth/verify-plugin', array(
                    'headers' => array('Content-Type' => 'application/json'),
                    'body'    => wp_json_encode($body),
                    'timeout' => 20,
                ));

                if (is_wp_error($response)) {
                    wp_send_json_error('Verification request failed: ' . $response->get_error_message());
                }

                $status_code = wp_remote_retrieve_response_code($response);
                $response_body = wp_remote_retrieve_body($response);
                $json = json_decode($response_body, true);
                if (json_last_error() !== JSON_ERROR_NONE) {
                    $parse_error = json_last_error_msg();
                    wp_send_json_error('Invalid server response: ' . $parse_error);
                }

                if ($status_code !== 200) {
                    $serverMsg = isset($json['message']) ? $json['message'] : 'Server error';
                    $detail = isset($json['data']['summary']) ? (' - ' . $json['data']['summary']) : '';
                    wp_send_json_error($serverMsg . $detail);
                }

                if (!($json['success'] ?? false)) {
                    $summary = isset($json['data']['summary']) ? $json['data']['summary'] : ($json['message'] ?? 'Verification failed.');
                    wp_send_json_error($summary);
                }

                // Success
                $linked = isset($json['data']['linked']) ? (bool)$json['data']['linked'] : false;
                $message = $linked
                    ? 'Verified and linked successfully. Return to your onboarding screen to continue.'
                    : 'Verified successfully. If you have an onboarding screen, you can proceed there.';

                wp_send_json_success(array(
                    'message' => $message,
                    'linked' => $linked,
                ));
                
            } catch (Exception $e) {
                wp_send_json_error('Failed to verify: ' . $e->getMessage());
            }
        } else {
             wp_send_json_error('You must be logged in to connect.');
        }
    }
    
    public function generate_app_password($app_name) {
        // Check if WP_Application_Passwords is available (WordPress 5.6+)
        if (!class_exists('WP_Application_Passwords')) {
            throw new Exception('Application passwords require WordPress 5.6 or higher');
        }
        
        // Get current user
        $user = wp_get_current_user();
        if (!$user->exists()) {
            throw new Exception('User not found');
        }
        
        // Create the application password
        $password_data = WP_Application_Passwords::create_new_application_password(
            $user->ID,
            array(
                'name' => $app_name,
                'capabilities' => array('read', 'edit_posts')
            )
        );
        
        if (is_wp_error($password_data)) {
            throw new Exception('Failed to generate app password.');
        }
        
        // Store the password data for later use
        $this->store_app_password_data($password_data);
        
        // Log the action
        
        
        return $password_data[0]; // Return the plain text password
    }
    
    private function store_app_password_data($password_data) {
        // Store the password data in WordPress options
        $stored_data = get_option('seo_pilot_app_passwords', array());
        $stored_data[] = array(
            'uuid' => $password_data[1]['uuid'],
            'name' => $password_data[1]['name'],
            'created' => $password_data[1]['created'],
            'last_used' => $password_data[1]['last_used'],
            'last_ip' => $password_data[1]['last_ip']
        );
        update_option('seo_pilot_app_passwords', $stored_data);
    }
    

    
    private function encrypt_payload($payload, $secret) {
        $iv_length = openssl_cipher_iv_length('aes-256-cbc');
        $iv = openssl_random_pseudo_bytes($iv_length);
        
        $json = json_encode($payload);
        $cipher = openssl_encrypt($json, 'aes-256-cbc', $secret, OPENSSL_RAW_DATA, $iv);
        
        // Combine IV + cipher and encode
        $encoded = base64_encode($iv . $cipher);
        
        // Make it URL safe
        return rtrim(strtr($encoded, '+/', '-_'), '=');
    }
    
    /**
     * Plugin activation hook
     */
    public function plugin_activated() {
        // Check for RankMath and Wordfence compatibility FIRST
        $this->check_compatibility();
        
        // Ensure Wordfence configuration runs on activation
        $this->ensure_wordfence_configuration();
        
        // Set activation flag AFTER compatibility check
        update_option('seo_pilot_activated', true);
        update_option('seo_pilot_activation_time', current_time('timestamp'));
        if (get_option('seo_pilot_strip_category_base') || get_option('seo_pilot_strip_tag_base')) {
            flush_rewrite_rules();
        }
    }
    
    /**
     * Check for plugin compatibility and configure accordingly
     */
    public function check_compatibility() {
        // Remove the flag check since we want this to run on every activation
        try {
            // Configure RankMath if present
            $this->configure_rankmath();
            
            // Configure Wordfence if present
            $this->configure_wordfence();
            
        } catch (Exception $e) {
            // Swallow errors silently in production
        }
    }

    /**
     * When enabled, remove /category/ from links and add rewrite rules.
     */
    public function enable_strip_category_base() {
        // Generate rewrite rules for each category path (handles parents)
        $categories = get_categories(array('hide_empty' => false));
        if (is_wp_error($categories)) {
            return;
        }
        foreach ($categories as $category) {
            $path = get_category_parents($category, false, '/', true);
            if (!is_string($path)) {
                $path = $category->slug . '/';
            }
            $path = trim($path, '/');
            if ($path === '') { continue; }

            // Archive
            add_rewrite_rule('^' . preg_quote($path, '#') . '/?$', 'index.php?category_name=' . $path, 'top');
            // Pagination
            add_rewrite_rule('^' . preg_quote($path, '#') . '/page/([0-9]{1,})/?$', 'index.php?category_name=' . $path . '&paged=$matches[1]', 'top');
            // Feeds
            add_rewrite_rule('^' . preg_quote($path, '#') . '/(feed|rdf|rss|rss2|atom)/?$', 'index.php?category_name=' . $path . '&feed=$matches[1]', 'top');
        }
    }

    /**
     * Filter generated category links to drop the base segment.
     */
    public function filter_category_link($termlink, $term_id) {
        $home = home_url('/');
        $termlink = trailingslashit($termlink);
        // Compute the current category base
        $category_base = get_option('category_base');
        $category_base = $category_base ? trim($category_base, '/') : 'category';
        $replace = trailingslashit($home . $category_base . '/');
        if (strpos($termlink, $replace) === 0) {
            $termlink = $home . substr($termlink, strlen($replace));
        }
        return $termlink;
    }

    /**
     * Inject custom rewrite rules so changes work without manual flushing.
     */
    public function inject_rewrite_rules($rules) {
        $custom = array();
        if (get_option('seo_pilot_strip_category_base')) {
            $categories = get_categories(array('hide_empty' => false));
            if (!is_wp_error($categories)) {
                foreach ($categories as $category) {
                    $path = get_category_parents($category, false, '/', true);
                    if (!is_string($path)) {
                        $path = $category->slug . '/';
                    }
                    $path = trim($path, '/');
                    if ($path === '') { continue; }
                    $escaped = preg_quote($path, '#');
                    $custom['^' . $escaped . '/?$'] = 'index.php?category_name=' . $path;
                    $custom['^' . $escaped . '/page/([0-9]{1,})/?$'] = 'index.php?category_name=' . $path . '&paged=$matches[1]';
                    $custom['^' . $escaped . '/(feed|rdf|rss|rss2|atom)/?$'] = 'index.php?category_name=' . $path . '&feed=$matches[1]';
                }
            }
        }
        if (get_option('seo_pilot_strip_tag_base')) {
            $tags = get_tags(array('hide_empty' => false));
            if (!is_wp_error($tags)) {
                foreach ($tags as $tag) {
                    $slug = $tag->slug;
                    if ($slug === '') { continue; }
                    $escaped = preg_quote($slug, '#u');
                    $custom['^' . $escaped . '/?$'] = 'index.php?tag=' . $slug;
                    $custom['^' . $escaped . '/page/([0-9]{1,})/?$'] = 'index.php?tag=' . $slug . '&paged=$matches[1]';
                    $custom['^' . $escaped . '/(feed|rdf|rss|rss2|atom)/?$'] = 'index.php?tag=' . $slug . '&feed=$matches[1]';
                }
            }
        }
        // Prepend our rules so they take precedence
        return $custom + $rules;
    }
    
    /**
     * When enabled, remove /tag/ from links and add rewrite rules.
     */
    public function enable_strip_tag_base() {
        // Generate rewrite rules for each tag
        $tags = get_tags(array('hide_empty' => false));
        if (is_wp_error($tags)) {
            return;
        }
        foreach ($tags as $tag) {
            $path = $tag->slug;
            if ($path === '') { continue; }

            // Archive
            add_rewrite_rule('^' . preg_quote($path, '#u') . '/?$', 'index.php?tag=' . $path, 'top');
            // Pagination
            add_rewrite_rule('^' . preg_quote($path, '#u') . '/page/([0-9]{1,})/?$', 'index.php?tag=' . $path . '&paged=$matches[1]', 'top');
            // Feeds
            add_rewrite_rule('^' . preg_quote($path, '#u') . '/(feed|rdf|rss|rss2|atom)/?$', 'index.php?tag=' . $path . '&feed=$matches[1]', 'top');
        }
    }

    /**
     * Filter generated tag links to drop the base segment.
     */
    public function filter_tag_link($termlink, $term_id) {
        $home = home_url('/');
        $termlink = trailingslashit($termlink);
        // Compute the current tag base
        $tag_base = get_option('tag_base');
        $tag_base = $tag_base ? trim($tag_base, '/') : 'tag';
        $replace = trailingslashit($home . $tag_base . '/');
        if (strpos($termlink, $replace) === 0) {
            $termlink = $home . substr($termlink, strlen($replace));
        }
        return $termlink;
    }

    /**
     * Map top-level pretty URLs that match a tag slug to the tag archive.
     * Avoids collisions with existing pages/posts or other tax queries.
     */
    public function map_tag_request_without_base($query_vars) {
        if (is_admin()) { return $query_vars; }
        if (!empty($query_vars['tag']) || !empty($query_vars['category_name']) || !empty($query_vars['name'])) {
            return $query_vars; // another resolver has already claimed the request
        }
        if (!isset($query_vars['pagename']) && !isset($query_vars['attachment']) && !isset($query_vars['preview'])) {
            return $query_vars; // not a simple pagename request
        }
        $slug = isset($query_vars['pagename']) ? $query_vars['pagename'] : '';
        if ($slug === '') { return $query_vars; }

        // Decode percent-encoded UTF-8 so non-ASCII slugs match stored term slugs
        $decoded = rawurldecode($slug);
        $term = get_term_by('slug', $decoded, 'post_tag');
        if ($term && !is_wp_error($term)) {
            // Ensure no page/post exists with this slug at root; if it does, let core handle it
            if (get_page_by_path($decoded)) { return $query_vars; }
            $query_vars['tag'] = $term->slug;
            unset($query_vars['pagename']);
        }
        return $query_vars;
    }
    
    /**
     * Configure RankMath for Headless CMS Support
     */
    private function configure_rankmath() {
        // Check if RankMath is active
        if (!$this->is_rankmath_active()) {
            return;
        }
        
        // Enable Headless CMS Support
        $this->enable_rankmath_headless_support();
        
        // Configuration complete
    }
    
    /**
     * Check if RankMath plugin is active
     */
    private function is_rankmath_active() {
        return class_exists('RankMath') || 
               function_exists('rank_math') || 
               $this->is_plugin_active('seo-by-rank-math/rank-math.php') ||
               $this->is_plugin_active('rank-math/rank-math.php');
    }
    
    /**
     * Enable RankMath Headless CMS Support
     */
    private function enable_rankmath_headless_support() {
        // Method 1: Try to update RankMath options directly
        $rankmath_options = get_option('rank-math-options-general', array());
        
        // Enable Headless CMS Support
        $rankmath_options['headless_support'] = 'on';
        
        // Update the option
        update_option('rank-math-options-general', $rankmath_options);
        
        // Method 2: Try using RankMath's API if available
        if (function_exists('rank_math')) {
            try {
                $rankmath = rank_math();
                if (method_exists($rankmath, 'settings')) {
                    $settings = $rankmath->settings();
                    if (method_exists($settings, 'set')) {
                        $settings->set('general', 'headless_support', 'on');
                    }
                }
            } catch (Exception $e) {
                // Fail silently in production
            }
        }
    }
    
    /**
     * Configure Wordfence firewall allowlist
     */
    private function configure_wordfence() {
        // Check if Wordfence is active
        if (!$this->is_wordfence_active()) {
            return;
        }
        
        // Add endpoint to firewall allowlist
        $this->add_wordfence_allowlist();
        
        // Log the configuration
        
    }
    
    /**
     * Check if Wordfence plugin is active
     */
    private function is_wordfence_active() {
        return class_exists('wordfence') || 
               function_exists('wfGetIP') || 
               $this->is_plugin_active('wordfence/wordfence.php');
    }
    
    /**
     * Add endpoint to Wordfence firewall allowlist
     */
    private function add_wordfence_allowlist() {
        $endpoint = '/wp-json/rankmath/v1/updateMeta';
        
        
        // Check if already added using Wordfence's config API (correct way, since it's a custom DB table)
        if (class_exists('wfConfig')) {
            $key = 'allowlistedURLs'; // Use 'whitelistedURLs' if your Wordfence version is older than ~7.5
            $allowlist = wfConfig::get_ser($key, array());
            if (is_array($allowlist)) {
                foreach ($allowlist as $entry) {
                    if (isset($entry['path']) && $entry['path'] === $endpoint) {
                        return true; // Already exists
                    }
                }
            }
        }
        
        // Try to update via Wordfence's WAF (this is the reliable method)
        if (class_exists('wfWAF') && method_exists('wfWAF', 'getInstance')) {
            try {
                $waf = wfWAF::getInstance();
                if ($waf && method_exists($waf, 'whitelistRuleForParam')) {
                    $ip_fallback = '';
                    $raw_ip = filter_input( INPUT_SERVER, 'REMOTE_ADDR', FILTER_UNSAFE_RAW );
                    if ( is_string( $raw_ip ) ) {
                        $raw_ip = wp_unslash( $raw_ip );
                        $validated = filter_var( $raw_ip, FILTER_VALIDATE_IP );
                        $ip_fallback = $validated ? $validated : '';
                    }
                    $data = array(
                        'timestamp' => time(),
                        'description' => 'Promoto AI Integration - RankMath API endpoint',
                        'ip' => class_exists('wfUtils') ? wfUtils::getIP() : $ip_fallback,
                        'disabled' => false,
                        'userID' => get_current_user_id()
                    );
                    
                    $waf->whitelistRuleForParam($endpoint, 'none', 'all', $data);
                    return true;
                }
            } catch (Exception $e) {
                // Ignore failures silently
            }
        }
        
        // If we reach here, addition failed
        return false;
    }
    
    /**
     * Helper function to check if a plugin is active
     */
    private function is_plugin_active($plugin) {
        if (!function_exists('is_plugin_active')) {
            include_once(ABSPATH . 'wp-admin/includes/plugin.php');
        }
        return function_exists('is_plugin_active') ? is_plugin_active($plugin) : false;
    }
    

    
    /**
     * Ensure Wordfence configuration runs on every load
     */
    public function ensure_wordfence_configuration() {
        if (is_admin() && current_user_can('manage_options') && $this->is_wordfence_active()) {
            $result = $this->add_wordfence_allowlist();
            update_option('seo_pilot_wordfence_last_check', array(
                'timestamp' => current_time('timestamp'),
                'success' => $result,
                'endpoint' => '/wp-json/rankmath/v1/updateMeta'
            ));
        }
    }
    

    

    

    

    

}

// Initialize the plugin
new SEOPilot(); 