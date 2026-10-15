import type { Article, ArticleStatus } from '../../domain/types.ts';
import { HttpError } from '../../util/errors.ts';
import { id, nowIso } from '../../util/ids.ts';
import { listReadable, loadOr404, representation } from '../guards.ts';
import { json, noContent } from '../responses.ts';
import { Router, type Ctx } from '../router.ts';
import { optionalEnum, optionalString, optionalStringArray, requireString } from '../validate.ts';

const STATUSES = ['draft', 'review', 'published'] as const;

export function articleRoutes(): Router {
    const router = new Router();

    /**
     * The clearest demonstration of row-level policy in this codebase: the same
     * request returns published articles to a guest, the guest's view plus
     * their own drafts to an author, and everything — `internalNotes` included
     * — to an editor. No branching in the handler.
     */
    router.get('/articles', async (ctx: Ctx) => {
        const status = ctx.url.searchParams.get('status');
        const author = ctx.url.searchParams.get('author');
        const articles = await ctx.services.db.articles.find(
            (article) =>
                (!status || article.status === status) && (!author || article.authorId === author),
        );
        const visible = listReadable(ctx, { action: 'read', resource: 'article' }, asRecords(articles));
        return json({ data: visible, count: visible.length });
    });

    router.get('/articles/:id', async (ctx: Ctx) => {
        const article = await loadOr404(ctx.services.db.articles.get(ctx.params.id ?? ''), 'Article');
        const decision = ctx.authorize({ action: 'read', resource: 'article', record: asRecord(article) });
        return json({ data: ctx.services.authz.project(decision, asRecord(article)) });
    });

    router.post('/articles', async (ctx: Ctx) => {
        const body = await ctx.body();
        const draft: Article = {
            id: id('art'),
            authorId: ctx.actor.id ?? '',
            title: '',
            body: '',
            summary: '',
            tags: [],
            status: 'draft',
            publishedAt: null,
            internalNotes: '',
            createdAt: nowIso(),
            updatedAt: nowIso(),
        };

        // Authorizing against the record-to-be is what makes `create:own`
        // meaningful: the draft is stamped with the caller's id first, so the
        // ownership resolver has something true to evaluate.
        const decision = ctx.authorize({
            action: 'create',
            resource: 'article',
            record: asRecord(draft),
            input: body,
        });
        const input = ctx.services.authz.sanitize(decision, body);

        const article: Article = {
            ...draft,
            title: requireString(input, 'title', { max: 200 }),
            body: requireString(input, 'body', { max: 100_000 }),
            summary: optionalString(input, 'summary', 500) ?? '',
            tags: optionalStringArray(input, 'tags') ?? [],
        };
        await ctx.services.db.articles.insert(article);

        const view = representation(ctx, 'article', asRecord(article));
        return json(view, { status: 201 });
    });

    /**
     * The update rule for authors carries a condition over both the record
     * (`$.article.status`) and the request body (`$.input.status`), so an
     * author may move a draft into review but can never patch it to
     * `published` — while an editor's unconditional `update:any` rule can.
     */
    router.patch('/articles/:id', async (ctx: Ctx) => {
        const article = await loadOr404(ctx.services.db.articles.get(ctx.params.id ?? ''), 'Article');
        const body = await ctx.body();
        const decision = ctx.authorize({
            action: 'update',
            resource: 'article',
            record: asRecord(article),
            input: body,
        });
        const input = ctx.services.authz.sanitize(decision, body);

        const patch: Partial<Article> = { updatedAt: nowIso() };
        const title = optionalString(input, 'title', 200);
        if (title !== undefined) patch.title = title;
        const articleBody = optionalString(input, 'body', 100_000);
        if (articleBody !== undefined) patch.body = articleBody;
        const summary = optionalString(input, 'summary', 500);
        if (summary !== undefined) patch.summary = summary;
        const tags = optionalStringArray(input, 'tags');
        if (tags !== undefined) patch.tags = tags;
        const notes = optionalString(input, 'internalNotes', 5000);
        if (notes !== undefined) patch.internalNotes = notes;
        const status = optionalEnum<ArticleStatus>(input, 'status', STATUSES);
        if (status !== undefined) {
            patch.status = status;
            patch.publishedAt = status === 'published' ? (article.publishedAt ?? nowIso()) : null;
        }

        const updated = await ctx.services.db.articles.update(article.id, patch);
        if (!updated) throw HttpError.notFound('Article');
        const view = representation(ctx, 'article', asRecord(updated));
        return json(view);
    });

    router.delete('/articles/:id', async (ctx: Ctx) => {
        const article = await loadOr404(ctx.services.db.articles.get(ctx.params.id ?? ''), 'Article');
        ctx.authorize({ action: 'delete', resource: 'article', record: asRecord(article) });
        await ctx.services.db.comments.removeWhere((comment) => comment.articleId === article.id);
        await ctx.services.db.articles.remove(article.id);
        return noContent();
    });

    /**
     * A custom action — CRUD does not describe "publish", so the policy models
     * it as its own verb. Authors may publish their own article once it has
     * cleared review; editors may publish anything, but only inside the
     * scheduled window (`.during(BUSINESS_HOURS)`), which surfaces as an
     * `out_of_schedule` denial rather than a flat "forbidden".
     */
    router.post('/articles/:id/publish', async (ctx: Ctx) => {
        const article = await loadOr404(ctx.services.db.articles.get(ctx.params.id ?? ''), 'Article');
        if (article.status === 'published') {
            throw HttpError.conflict('This article is already published.');
        }
        ctx.authorize({ action: 'publish', resource: 'article', record: asRecord(article) });

        const updated = await ctx.services.db.articles.update(article.id, {
            status: 'published',
            publishedAt: nowIso(),
            updatedAt: nowIso(),
        });
        if (!updated) throw HttpError.notFound('Article');
        const view = representation(ctx, 'article', asRecord(updated));
        return json(view);
    });

    return router;
}

function asRecord(article: Article): Record<string, unknown> {
    return article as unknown as Record<string, unknown>;
}

function asRecords(articles: Article[]): Record<string, unknown>[] {
    return articles as unknown as Record<string, unknown>[];
}
