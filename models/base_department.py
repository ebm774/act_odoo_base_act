from odoo import models, fields, api, _
from odoo.exceptions import UserError


class BaseDepartment(models.Model):
    _name = 'base_act.department'
    _description = 'Base Department'
    # _inherit = 'res.groups'
    _rec_name = 'name'
    name = fields.Char('Department Name', required=True)
    user_ids = fields.Many2many(
        'res.users',
        'base_act_department_users_rel',
        'department_id',
        'user_id',
        string='Department Users'
    )


    # department_code = fields.Char(string='Department Code', size=10)
    # manager_id = fields.Many2one('res.users', string='Department Manager')

    #
    # @api.model
    # def _get_default_category(self):
    #     return self.env.ref('base.module_category_administration', raise_if_not_found=False)

    # category_id = fields.Many2one(
    #     'ir.module.category',
    #     string='Application',
    #     default=_get_default_category
    # )

    # @api.model_create_multi
    # def create(self, vals_list):
    #     """Ensure departments are created with proper category and base permissions"""
    #     for vals in vals_list:
    #         if not vals.get('category_id'):
    #             vals['category_id'] = self.env.ref('base.module_category_administration').id
    #         if not vals.get('implied_ids'):
    #             vals['implied_ids'] = [(4, self.env.ref('base.group_user').id)]
    #
    #     return super().create(vals_list)