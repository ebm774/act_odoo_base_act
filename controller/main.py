# -*- coding: utf-8 -*-

from odoo import http, _, fields, api
from odoo.http import request
from odoo.addons.web.controllers.home import Home
import datetime
import json
import logging
import secrets


_logger = logging.getLogger(__name__)


class LoginController(Home):

    @http.route('/web/login', type='http', auth="none", website=True, sitemap=False)
    def web_login(self, redirect=None, **kw):
        """Override login to add tag authentication option"""

        # Handle tag authentication if submitted
        if request.httprequest.method == 'POST' and kw.get('auth_method') == 'tag':
            tag_number = kw.get('tag_number', '').strip()

            if tag_number and tag_number.isdigit():
                try:
                    # Search for users with this tag
                    connector = request.env['base_act.ldap.connector'].sudo()
                    matching_users = connector.search_users_by_tag(tag_number)


                    if len(matching_users) == 1:
                        # Single user found - authenticate directly
                        dn, attrs = matching_users[0]
                        login = attrs.get('sAMAccountName', [b''])[0].decode('utf-8')
                        # Auto-login with tag (create session without password)
                        return self._process_tag_login(login, attrs, redirect)

                    elif len(matching_users) == 0:
                        _logger.warning(f"Tag authentication failed: No user found for tag {tag_number}")
                        error_message = "Invalid tag number. Please check your tag or use password login."
                        return request.redirect(f'/web/login?error={error_message}&auth_method=tag')

                    else:
                        # Multiple users found - this shouldn't happen but let's handle it
                        _logger.warning(f"Tag authentication: Multiple users found for tag {tag_number}")
                        error_message = "Multiple users found for this tag. Please contact your administrator."
                        return request.redirect(f'/web/login?error={error_message}&auth_method=tag')

                except Exception as e:
                    _logger.error(f"Tag authentication error: {e}")
                    values = request.params.copy()
                    values['error'] = _(
                        "Authentication system temporarily unavailable. Please try password login or contact support.")
                    return request.render('web.login', values)
            else:
                _logger.warning(f"Tag authentication failed: Invalid tag format '{tag_number}'")
                values = request.params.copy()
                values['error'] = _("Invalid tag format. Please scan a valid tag or use password login.")
                return request.render('web.login', values)

        # Default login page with auth method selector
        response = super().web_login(redirect, **kw)

        return response

    def _process_tag_login(self, login, ldap_attrs, redirect=None):
        """Process login for tag-authenticated user"""
        _logger.info("_process_tag_login")
        try:
            # Create or get user
            users = request.env['res.users'].sudo()
            user = users.search([('login', '=', login)], limit=1)
            _logger.info(f"login : {login}")

            if user :
                _logger.info("Updating existing user")
                user._sync_ldap_user(ldap_attrs, login)

                request.env.cr.commit()
                _logger.info("User sync completed")

                # Generate temporary password and temporarily disable LDAP
                temp_password = secrets.token_urlsafe(32)
                _logger.info("Generated temp password")

                user.sudo().write({
                    'password': temp_password,
                    'is_ldap_user': False,
                })
                _logger.info("Updated user with temp password")
                request.env.cr.commit()
                _logger.info("Committed temp password")


                # Authenticate normally (server-side API expects positional args)
                _logger.info("About to call session.authenticate")
                _logger.info("db name is : %s", request.db)

                credential = {
                    'type': 'password',  # required by Odoo
                    'login': login,  # the user login you found
                    'password': temp_password,  # placeholder; won’t be used if you short-circuit
                }

                uid = request.session.authenticate(request.db, credential)
                _logger.info(f"Authentication returned: {uid}")

                if uid:
                    _logger.info("Authentication successful via temp password")
                    # Re-enable LDAP and clear password
                    user.sudo().write({
                        'password': '',
                        'is_ldap_user': True,
                    })
                    request.env.cr.commit()
                    _logger.info("Restored user settings")

                    return request.redirect(redirect or '/web')
            else:
                error_message = "You tag does not give you access to this software, please contact your system administrator."
                return request.redirect(f'/web/login?error={error_message}&auth_method=tag')


        except Exception as e:
            request.env.cr.rollback()
            values = request.params.copy()
            values['error'] = _("Authentication failed: Unable to create or access user account")
            return request.render('web.login', values)