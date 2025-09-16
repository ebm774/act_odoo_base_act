# -*- coding: utf-8 -*-
from odoo import models, fields, api


class BaseCompanyMixin(models.AbstractModel):
    """
    Mixin to add company and currency support to any model
    Used across multiple modules for consistent company/currency handling
    """
    _name = 'base_act.company'
    _description = 'Base Company and Currency Mixin'

    company_id = fields.Many2one(
        'res.company',
        string='Company',
        required=True,
        default=lambda self: self.env.company,
        help='Company this record belongs to'
    )

    currency_id = fields.Many2one(
        'res.currency',
        related='company_id.currency_id',
        string='Currency',
        readonly=True,
        store=True,
        help='Currency of the company'
    )