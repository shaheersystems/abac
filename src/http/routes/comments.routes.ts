import type { Comment } from '../../domain/types.ts';
import { HttpError } from '../../util/errors.ts';
import { id, nowIso } from '../../util/ids.ts';
import { listReadable, loadOr404, representation } from '../guards.ts';
import { json, noContent } from '../responses.ts';
import { Router, type Ctx } from '../router.ts';
import { requireString } from '../validate.ts';

export function commentRoutes(): Router {
    const router = new Router();

    router.get('/articles/:id/comments', async (ctx: Ctx) => {
        const article = await loadOr404(ctx.services.db.articles.get(ctx.params.id ?? ''), 'Article');
        // Reading the comments implies reading the article they hang off.
        ctx.authorize({ action: 'read', resource: 'article', record: asRecord(article) });

        const comments = await ctx.services.db.comments.find((c) => c.articleId === article.id);
        const visible = listReadable(ctx, { action: 'read', resource: 'comment' }, asRecords(comments));
        return json({ data: visible, count: visible.length });
    });

    router.post('/articles/:id/comments', async (ctx: Ctx) => {
        const article = await loadOr404(ctx.services.db.articles.get(ctx.params.id ?? ''), 'Article');
        ctx.authorize({ action: 'read', resource: 'article', record: asRecord(article) });

        const body = await ctx.body();
        const draft: Comment = {
            id: id('cmt'),
            articleId: article.id,
            authorId: ctx.actor.id ?? '',
            body: '',
            flagged: false,
            createdAt: nowIso(),
            updatedAt: nowIso(),
        };
        const decision = ctx.authorize({
            action: 'create',
            resource: 'comment',
            record: asRecord(draft),
            input: { ...body, articleId: article.id },
        });
        const input = ctx.services.authz.sanitize(decision, { ...body, articleId: article.id });

        const comment: Comment = { ...draft, body: requireString(input, 'body', { max: 5000 }) };
        await ctx.services.db.comments.insert(comment);

        const view = representation(ctx, 'comment', asRecord(comment));
        return json(view, { status: 201 });
    });

    /** Authors edit their own text; editors may only flip `flagged`. */
    router.patch('/comments/:id', async (ctx: Ctx) => {
        const comment = await loadOr404(ctx.services.db.comments.get(ctx.params.id ?? ''), 'Comment');
        const body = await ctx.body();
        const decision = ctx.authorize({
            action: 'update',
            resource: 'comment',
            record: asRecord(comment),
            input: body,
        });
        const input = ctx.services.authz.sanitize(decision, body);

        const patch: Partial<Comment> = { updatedAt: nowIso() };
        if (typeof input.body === 'string') patch.body = input.body;
        if (typeof input.flagged === 'boolean') patch.flagged = input.flagged;

        const updated = await ctx.services.db.comments.update(comment.id, patch);
        if (!updated) throw HttpError.notFound('Comment');
        const view = representation(ctx, 'comment', asRecord(updated));
        return json(view);
    });

    router.delete('/comments/:id', async (ctx: Ctx) => {
        const comment = await loadOr404(ctx.services.db.comments.get(ctx.params.id ?? ''), 'Comment');
        ctx.authorize({ action: 'delete', resource: 'comment', record: asRecord(comment) });
        await ctx.services.db.comments.remove(comment.id);
        return noContent();
    });

    return router;
}

function asRecord(value: { id: string }): Record<string, unknown> {
    return value as unknown as Record<string, unknown>;
}

function asRecords(values: { id: string }[]): Record<string, unknown>[] {
    return values as unknown as Record<string, unknown>[];
}
