<?php
/**
 * Plugin Name: Disable XML-RPC Pingback
 * Description: Disable pingback.ping xmlrpc method to prevent WordPress from participating in DDoS attacks.
 * More info at: https://docs.bitnami.com/general/apps/wordpress/troubleshooting/xmlrpc-and-pingback/
 */

if ( ! defined( 'WP_CLI' ) ) {
    // remove x-pingback HTTP header
    add_filter( "wp_headers", function( $headers ) {
        if ( isset( $headers['X-Pingback'] ) ) {
            unset( $headers['X-Pingback'] );
        }
        return $headers;
    });
    // disable pingbacks
    add_filter( "xmlrpc_methods", function( $methods ) {
        if ( isset( $methods['pingback.ping'] ) ) {
            unset( $methods['pingback.ping'] );
        }
        return $methods;
    });
}
