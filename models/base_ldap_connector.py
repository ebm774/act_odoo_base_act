# -*- coding: utf-8 -*-
from odoo import models, fields, api, tools
import ldap
import ldap.filter
import logging
from contextlib import contextmanager

_logger = logging.getLogger(__name__)



class LDAPConnector(models.AbstractModel):
    """Abstract model providing LDAP connection functionality
    Other modules can inherit this to get LDAP capabilities"""

    _name = 'base_act.ldap.connector'
    _description = 'LDAP Connector Service'

    @api.model
    @tools.ormcache()
    def get_ldap_config(self):
        """Get LDAP configuration from system parameters"""

        _logger.info("##############################")
        _logger.info("get_ldap_config")
        _logger.info("##############################")

        ICP = self.env['ir.config_parameter'].sudo()
        return {
            'server_local': ICP.get_param('base_act.ldap_server_local', ''),
            'bind_dn': ICP.get_param('base_act.ldap_bind_dn', ''),
            'bind_password': ICP.get_param('base_act.ldap_bind_password', ''),
            'base_dn': ICP.get_param('base_act.ldap_base_dn', 'DC=autocontrole,DC=be'),
            'timeout': int(ICP.get_param('base_act.ldap_timeout', '5')),
        }

    @contextmanager
    def ldap_connection(self, bind_dn=None, bind_password=None):
        """Context manager for LDAP connections"""
        config = self.get_ldap_config()
        conn = None
        ##

        # If no specific bind credentials, use service account
        if not bind_dn:
            bind_dn = config['bind_dn']
            bind_password = config['bind_password']

        servers = []
        if config.get('server_local'):
            servers.append(config['server_local'])

        last_error = None
        for server in servers:
            try:
                _logger.info(f"[LDAP] Attempting connection to: {server}")
                _logger.info(f"[LDAP] Using bind DN: {bind_dn}")

                conn = ldap.initialize(server)
                conn.set_option(ldap.OPT_REFERRALS, 0)
                conn.set_option(ldap.OPT_NETWORK_TIMEOUT, config['timeout'])

                # Try simple bind
                conn.protocol_version = ldap.VERSION3
                conn.simple_bind_s(bind_dn, bind_password)

                _logger.info(f"[LDAP] Successfully connected to {server}")
                yield conn
                return

            except ldap.INVALID_CREDENTIALS as e:
                last_error = e
                _logger.error(f"[LDAP] Invalid credentials for {bind_dn}: {e}")

            except Exception as e:
                last_error = e
                _logger.error(f"[LDAP] Failed to connect to {server}: {str(e)}")

            finally:
                if conn:
                    try:
                        conn.unbind()
                    except:
                        pass

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
                ['sAMAccountName', 'displayName', 'mail', 'memberOf', 'userPrincipalName', 'employeeID',
                 'EmployeeNumber']
            )

            # Fixed: Filter out referrals and find actual user data
            for entry in result:
                if isinstance(entry, tuple) and len(entry) == 2:
                    dn, attrs = entry
                    #  Skip LDAP referrals (they have None attrs or list attrs)
                    if attrs and isinstance(attrs, dict) and 'sAMAccountName' in attrs:
                        _logger.debug(f"[LDAP] Found user: {dn}")
                        return (dn, attrs)
                    else:
                        _logger.debug(f"[LDAP] Skipping referral or invalid entry: {entry}")

        _logger.debug(f"[LDAP] User {login} not found")
        return None

    @api.model
    def authenticate_user(self, login, password):
        """Authenticate a user against LDAP"""

        _logger.info("##############################")
        _logger.info("authenticate_user")
        _logger.info("##############################")

        config = self.get_ldap_config()


        user_data = self._search_user_with_config(login, config)
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

    def _search_user_with_config(self, login, config):
        """Search user with provided config"""
        with self._ldap_connection_with_config(config) as conn:
            search_filter = f"(&(objectClass=user)(sAMAccountName={ldap.filter.escape_filter_chars(login)}))"
            result = conn.search_s(
                config['base_dn'],
                ldap.SCOPE_SUBTREE,
                search_filter,
                ['sAMAccountName', 'displayName', 'mail', 'memberOf', 'userPrincipalName', 'employeeID',
                 'EmployeeNumber']
            )
            # ✅ Your existing referral filtering logic here
            for entry in result:
                if isinstance(entry, tuple) and len(entry) == 2:
                    dn, attrs = entry
                    if attrs and isinstance(attrs, dict) and 'sAMAccountName' in attrs:
                        return (dn, attrs)
            return None

    @contextmanager
    def _ldap_connection_with_config(self, config, bind_dn=None, bind_password=None):
        """Context manager for LDAP connections using provided config"""
        conn = None

        # If no specific bind credentials, use service account from config
        if not bind_dn:
            bind_dn = config['bind_dn']
            bind_password = config['bind_password']

        servers = []
        if config.get('server_local'):
            servers.append(config['server_local'])

        last_error = None
        for server in servers:
            try:
                _logger.info(f"[LDAP] Attempting connection to: {server}")
                _logger.info(f"[LDAP] Using bind DN: {bind_dn}")

                conn = ldap.initialize(server)
                conn.set_option(ldap.OPT_REFERRALS, 0)
                conn.set_option(ldap.OPT_NETWORK_TIMEOUT, config['timeout'])

                # Try simple bind
                conn.protocol_version = ldap.VERSION3
                conn.simple_bind_s(bind_dn, bind_password)

                _logger.info(f"[LDAP] Successfully connected to {server}")
                yield conn
                return

            except ldap.INVALID_CREDENTIALS as e:
                last_error = e
                _logger.error(f"[LDAP] Invalid credentials for {bind_dn}: {e}")

            except Exception as e:
                last_error = e
                _logger.error(f"[LDAP] Failed to connect to {server}: {str(e)}")

            finally:
                if conn:
                    try:
                        conn.unbind()
                    except:
                        pass

        # If we get here, all servers failed
        raise Exception(f"Could not connect to any LDAP server. Last error: {last_error}")

    @api.model
    def search_users_by_tag(self, tag_number):
        """Search for users by tag number (stored in mail attribute)"""
        _logger.info("##############################")
        _logger.info(f"Searching users with tag: {tag_number}")


        config = self.get_ldap_config()
        matching_users = []

        with self.ldap_connection() as conn:
            # Search all users and check mail attribute
            # We search broadly because mail field might have the tag in various formats
            search_filter = "(&(objectClass=user)(employeeID=*))"

            result = conn.search_s(
                config['base_dn'],
                ldap.SCOPE_SUBTREE,
                search_filter,
                ['sAMAccountName', 'displayName', 'mail', 'memberOf', 'userPrincipalName', 'employeeID', 'EmployeeNumber']
            )

            for entry in result:
                # Check if entry is valid tuple with DN and attributes
                if not entry or not isinstance(entry, tuple) or len(entry) != 2:
                    continue

                dn, attrs = entry

                # Skip if attrs is None or not a dictionary
                if attrs is None or not isinstance(attrs, dict):
                    _logger.debug(f"Skipping entry with invalid attrs type: {type(attrs)}")
                    continue

                # Now safely access employeeID
                ldap_tag_values = attrs.get('employeeID', [])

                for ldap_tag_value in ldap_tag_values:
                    if isinstance(ldap_tag_value, bytes):
                        ldap_tag_value = ldap_tag_value.decode('utf-8')

                    # Check if this employeeID value matches the tag
                    if str(ldap_tag_value).strip() == str(tag_number).strip():
                        _logger.info(f"Found matching user: DN={dn}")
                        matching_users.append((dn, attrs))
                        break

        _logger.info(f"Found {len(matching_users)} users with tag {tag_number}")
        _logger.info("##############################")
        return matching_users

    @api.model
    def get_odoo_groups_from_ldap(self, member_of_list):
        """Extract Odoo group names from LDAP memberOf attribute"""

        _logger.info("##############################")
        _logger.info("get_odoo_groups_from_ldap")
        _logger.info("##############################")


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