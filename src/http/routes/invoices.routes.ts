import type { Invoice } from '../../domain/types.ts';
import { HttpError } from '../../util/errors.ts';
import { id, nowIso } from '../../util/ids.ts';
import { listReadable, loadOr404, representation } from '../guards.ts';
import { json, noContent } from '../responses.ts';
import { Router, type Ctx } from '../router.ts';
import { optionalString, requireNumber, requireString } from '../validate.ts';

/**
 * Billing. Every route here inherits a `require()` gate — `$.mfa == true` —
 * declared once in the policy and enforced by the engine, so there is not a
 * single MFA check in this file. A session that has not stepped up gets
 * `403 step_up_required` from the first check it attempts.
 */
export function invoiceRoutes(): Router {
    const router = new Router();

    router.get('/invoices', async (ctx: Ctx) => {
        const invoices = await ctx.services.db.invoices.list();
        const visible = listReadable(ctx, { action: 'read', resource: 'invoice' }, asRecords(invoices));
        return json({ data: visible, count: visible.length });
    });

    router.get('/invoices/:id', async (ctx: Ctx) => {
        const invoice = await loadOr404(ctx.services.db.invoices.get(ctx.params.id ?? ''), 'Invoice');
        const decision = ctx.authorize({ action: 'read', resource: 'invoice', record: asRecord(invoice) });
        return json({ data: ctx.services.authz.project(decision, asRecord(invoice)) });
    });

    router.post('/invoices', async (ctx: Ctx) => {
        const body = await ctx.body();
        const draft: Invoice = {
            id: id('inv'),
            ownerId: ctx.actor.id ?? '',
            customer: '',
            amount: 0,
            currency: 'EUR',
            status: 'draft',
            internalNotes: '',
            approvedBy: null,
            createdAt: nowIso(),
            updatedAt: nowIso(),
        };
        const decision = ctx.authorize({
            action: 'create',
            resource: 'invoice',
            record: asRecord(draft),
            input: body,
        });
        const input = ctx.services.authz.sanitize(decision, body);

        const invoice: Invoice = {
            ...draft,
            customer: requireString(input, 'customer', { max: 200 }),
            amount: requireNumber(input, 'amount', 0),
            currency: (optionalString(input, 'currency', 3) ?? 'EUR').toUpperCase(),
            internalNotes: optionalString(input, 'internalNotes', 5000) ?? '',
        };
        await ctx.services.db.invoices.insert(invoice);

        const view = representation(ctx, 'invoice', asRecord(invoice));
        return json(view, { status: 201 });
    });

    /**
     * Managers may edit invoices up to `APPROVAL_LIMIT`; above it the
     * condition fails and only an admin's unconditional rule applies. The
     * amount that matters is the *stored* one — a caller cannot lower the
     * amount and raise it again, because the condition reads `$.invoice.amount`
     * from the record, not from the body.
     */
    router.patch('/invoices/:id', async (ctx: Ctx) => {
        const invoice = await loadOr404(ctx.services.db.invoices.get(ctx.params.id ?? ''), 'Invoice');
        const body = await ctx.body();
        const decision = ctx.authorize({
            action: 'update',
            resource: 'invoice',
            record: asRecord(invoice),
            input: body,
        });
        const input = ctx.services.authz.sanitize(decision, body);

        const patch: Partial<Invoice> = { updatedAt: nowIso() };
        const customer = optionalString(input, 'customer', 200);
        if (customer !== undefined) patch.customer = customer;
        if (input.amount !== undefined) patch.amount = requireNumber(input, 'amount', 0);
        const currency = optionalString(input, 'currency', 3);
        if (currency !== undefined) patch.currency = currency.toUpperCase();
        const notes = optionalString(input, 'internalNotes', 5000);
        if (notes !== undefined) patch.internalNotes = notes;
        if (typeof input.status === 'string') {
            if (!['draft', 'approved', 'paid', 'void'].includes(input.status)) {
                throw HttpError.unprocessable('"status" must be draft, approved, paid or void.');
            }
            patch.status = input.status as Invoice['status'];
        }

        const updated = await ctx.services.db.invoices.update(invoice.id, patch);
        if (!updated) throw HttpError.notFound('Invoice');
        const view = representation(ctx, 'invoice', asRecord(updated));
        return json(view);
    });

    /** Custom action with a value ceiling — the classic approval limit. */
    router.post('/invoices/:id/approve', async (ctx: Ctx) => {
        const invoice = await loadOr404(ctx.services.db.invoices.get(ctx.params.id ?? ''), 'Invoice');
        ctx.authorize({ action: 'approve', resource: 'invoice', record: asRecord(invoice) });

        const updated = await ctx.services.db.invoices.update(invoice.id, {
            status: 'approved',
            approvedBy: ctx.actor.id,
            updatedAt: nowIso(),
        });
        if (!updated) throw HttpError.notFound('Invoice');
        const view = representation(ctx, 'invoice', asRecord(updated));
        return json(view);
    });

    router.delete('/invoices/:id', async (ctx: Ctx) => {
        const invoice = await loadOr404(ctx.services.db.invoices.get(ctx.params.id ?? ''), 'Invoice');
        ctx.authorize({ action: 'delete', resource: 'invoice', record: asRecord(invoice) });
        await ctx.services.db.invoices.remove(invoice.id);
        return noContent();
    });

    return router;
}

function asRecord(invoice: Invoice): Record<string, unknown> {
    return invoice as unknown as Record<string, unknown>;
}

function asRecords(invoices: Invoice[]): Record<string, unknown>[] {
    return invoices as unknown as Record<string, unknown>[];
}
