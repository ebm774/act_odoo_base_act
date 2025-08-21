# -*- coding: utf-8 -*-
from odoo import models, fields, api, tools
import ldap
import logging
from contextlib import contextmanager

_logger = logging.getLogger(__name__)


class LDAPConnector(models.AbstractModel):
    """Abstract model providing LDAP connection functionality
    Other modules can inherit this to get LDAP capabilities"""

    _name = 'base_act.ldap.connector'
    _description = 'LDAP Connector Service'

    @api.model
    def get_ldap_config(self):
        """Get LDAP configuration from system parameters"""
        ICP = self.env['ir.config_parameter'].sudo()
        return {
            'server_cloud': ICP.get_param('base_act.ldap_server_cloud', ''),
            'server_local': ICP.get_param('base_act.ldap_server_local', ''),
            'bind_dn': ICP.get_param('base_act.ldap_bind_dn', ''),
            'bind_password': ICP.get_param('base_act.ldap_bind_password', ''),
            'base_dn': ICP.get_param('base_act.ldap_base_dn', 'DC=autocontrole,DC=be'),
            'timeout': int(ICP.get_param('base_act.ldap_timeout', '5')),
        }

    @contextmanager
    def ldap_connection(self, bind_dn=None, bind_password=None):
        """Context manager for LDAP connections
        Try cloud first, then local"""
        config = self.get_ldap_config()
        conn = None

        # If no specific bind credentials, use service account
        if not bind_dn:
            bind_dn = config['bind_dn']
            bind_password = config['bind_password']

        servers = []
        if config['server_cloud']:
            servers.append(config['server_cloud'])
        if config['server_local']:
            servers.append(config['server_local'])

        last_error = None
        for server in servers:
            try:
                conn = ldap.initialize(server)
                conn.set_option(ldap.OPT_REFERRALS, 0)
                conn.set_option(ldap.OPT_NETWORK_TIMEOUT, config['timeout'])
                conn.simple_bind_s(bind_dn, bind_password)
                _logger.debug(f"Connected to LDAP server: {server}")
                yield conn
                return
            except Exception as e:
                last_error = e
                _logger.warning(f"Failed to connect to {server}: {str(e)}")
                if conn:
                    try:
                        conn.unbind()
                    except:
                        pass
                continue

        # If we get here, all servers failed
        raise Exception(f"Could not connect to any LDAP server. Last error: {last_error}")

    @api.model
    def search_user(self, login):
        """Search for a user in LDAP by login (sAMAccountName)"""
        config = self.get_ldap_config()

        with self.ldap_connection() as conn:
            search_filter = f"(&(objectClass=user)(sAMAccountName={ldap.filter.escape_filter_chars(login)}))"

            result = conn.search_s(
                config['base_dn'],
                ldap.SCOPE_SUBTREE,
                search_filter,
                ['sAMAccountName', 'displayName', 'mail', 'memberOf', 'userPrincipalName']
            )

            if result and result[0][1]:
                return result[0]  # Return (dn, attributes)
        return None

    @api.model
    def authenticate_user(self, login, password):
        """Authenticate a user against LDAP"""
        user_data = self.search_user(login)
        if not user_data:
            return False

        dn, attrs = user_data

        # Try to bind with user credentials
        try:
            with self.ldap_connection(bind_dn=dn, bind_password=password):
                return attrs  # Return user attributes on success
        except ldap.INVALID_CREDENTIALS:
            return False
        except Exception as e:
            _logger.error(f"LDAP authentication error for {login}: {str(e)}")
            return False

    @api.model
    def get_odoo_groups_from_ldap(self, member_of_list):
        """Extract Odoo group names from LDAP memberOf attribute"""
        odoo_groups = []
        for group_dn in member_of_list:
            if isinstance(group_dn, bytes):
                group_dn = group_dn.decode('utf-8')

            # Extract CN from DN for odoo_ groups
            if 'CN=odoo_' in group_dn:
                cn_part = group_dn.split(',')[0]
                group_name = cn_part.replace('CN=', '')
                if group_name.startswith('odoo_'):
                    odoo_groups.append(group_name)

        return odoo_groups