<?php
/**
 * Plugin Name: Disable XML-RPC Pingback
 * Description: Disable pingback.ping xmlrpc method to prevent WordPress from participating in DDoS attacks.
 * More info at: https://docs.bitnami.com/general/apps/wordpress/troubleshooting/xmlrpc-and-pingback/
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

if ( ! function_exists( 'add_filter' ) ) {
    /**
     * Stub for IDE.
     *
     * @param string   $tag           The name of the filter to hook the $callback to.
     * @param callable $callback      The callback to be run when the filter is applied.
     * @param int      $priority      Optional. Used to specify the order in which the functions associated with a particular filter are executed. Default 10.
     * @param int      $accepted_args Optional. The number of arguments the function accepts. Default 1.
     * @return true
     */
    function add_filter( $tag, $callback, $priority = 10, $accepted_args = 1 ) {
        return true;
    }
}

if ( ! defined( 'WP_CLI' ) ) {
    // remove x-pingback HTTP header
    add_filter( 'wp_headers', function( $headers ) {
        if ( isset( $headers['X-Pingback'] ) ) {
            unset( $headers['X-Pingback'] );
        }
        return $headers;
    });

    // disable pingbacks
    add_filter( 'xmlrpc_methods', function( $methods ) {
        if ( isset( $methods['pingback.ping'] ) ) {
            unset( $methods['pingback.ping'] );
        }
        return $methods;
    });
}

