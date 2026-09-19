"""REAL Lambda handler for Forums (replaces mock_handler).

Routes API Gateway proxy events, EventBridge group-lifecycle events, and
Scheduler sweep triggers through a single function (ND-1=A).

Wrapped by global_handler so no exception escapes (SECURITY-15).
Administrator → 403 on ALL operations including reads (BR-1).
"""
from __future__ import annotations

import json
import os
import re

from _conventions.authz import Principal, claims_to_headers, extract_claims
from _conventions.errors import AppError, global_handler, to_response
from _conventions.idempotency import IdempotencyStore
from _conventions.logger import set_correlation_id

from authz import (
    can_delete,
    can_edit,
    get_accessible_group_ids,
    require_author_or_leader,
    require_forum_create,
    require_group_access,
    require_manage,
    require_moderation,
    require_not_admin,
    require_pin_or_accept,
)
from consumers import CONSUMED_EVENT_TYPES, EventConsumer
from mention_client import MentionClient
from models import (
    RATE_LIMIT_POST_PER_HOUR,
    RATE_LIMIT_REPLY_PER_HOUR,
    now_iso,
    serialize_channel,
    serialize_follow,
    serialize_forum,
    serialize_post,
    serialize_reply,
    serialize_report,
    tokenize,
    validate_post_input,
    validate_reaction_kind,
    validate_reply_input,
)
from providers import EventPublisher
from repository import ForumsRepository
from sanitizer import sanitize_markdown
from sweep import SweepHandler

# --- Route table ---
OPERATIONS = {
    ("GET", "/forums"): "browseForums",
    ("POST", "/forums"): "createForum",
    ("PUT", "/forums/{id}"): "editForum",
    ("DELETE", "/forums/{id}"): "deleteForum",
    ("POST", "/forums/{id}/channels"): "createChannel",
    ("PUT", "/channels/{id}"): "editChannel",
    ("DELETE", "/channels/{id}"): "deleteChannel",
    ("GET", "/channels/{id}/posts"): "listPosts",
    ("POST", "/channels/{id}/posts"): "createPost",
    ("GET", "/posts/{id}"): "getThread",
    ("PUT", "/posts/{id}"): "editPost",
    ("DELETE", "/posts/{id}"): "deletePost",
    ("GET", "/posts/{id}/replies"): "listReplies",
    ("POST", "/posts/{id}/replies"): "createReply",
    ("PUT", "/replies/{id}"): "editReply",
    ("DELETE", "/replies/{id}"): "deleteReply",
    ("POST", "/posts/{id}/reactions"): "toggleReaction",
    ("POST", "/replies/{id}/reactions"): "toggleReplyReaction",
    ("POST", "/posts/{id}/pin"): "togglePin",
    ("POST", "/posts/{id}/accept"): "acceptAnswer",
    ("POST", "/posts/{id}/follow"): "toggleFollowPost",
    ("POST", "/channels/{id}/follow"): "toggleFollowChannel",
    ("GET", "/forums/follows"): "listFollows",
    ("POST", "/posts/{id}/report"): "reportPost",
    ("POST", "/replies/{id}/report"): "reportReply",
    ("GET", "/forums/moderation"): "moderationQueue",
    ("POST", "/forums/moderation/{id}/dismiss"): "dismissReport",
    ("POST", "/forums/moderation/{id}/action"): "actionReport",
    ("GET", "/forums/mention-suggest"): "mentionSuggest",
    ("GET", "/forums/search"): "searchForum",
}


def _compile(path: str) -> re.Pattern:
    return re.compile("^" + re.sub(r"\{([^}]+)\}", r"(?P<\1>[^/]+)", path) + "$")


_COMPILED = [(m, _compile(p), op) for (m, p), op in OPERATIONS.items()]


def _json_default(o):
    from decimal import Decimal
    if isinstance(o, Decimal):
        return int(o) if o == o.to_integral_value() else float(o)
    return str(o)


def _resp(status: int, body) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
        "body": json.dumps(body, default=_json_default) if body is not None else "",
    }


class Context:
    """Wires all components. Injected in tests."""

    def __init__(self, table=None, idempotency_table=None, mention_client=None,
                 events=None):
        if table is None:
            import boto3
            table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
        self.repo = ForumsRepository(table)
        idem_name = idempotency_table or os.environ.get("IDEMPOTENCY_TABLE", "")
        self.idempotency = IdempotencyStore(idem_name) if idem_name else None
        self.mentions = mention_client or MentionClient()
        self.events = events or EventPublisher()
        self.consumer = EventConsumer(self.repo, self.idempotency)
        self.sweep = SweepHandler(self.repo)


def _match(method: str, path: str):
    for m, rx, op in _COMPILED:
        if m == method:
            mm = rx.match(path)
            if mm:
                return op, mm.groupdict()
    return None, None


def _principal(event) -> Principal | None:
    claims = extract_claims(event)
    if not claims:
        return None
    return Principal.from_claims(claims)


def _bearer_token(event) -> str | None:
    headers = event.get("headers") or {}
    auth = headers.get("Authorization") or headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:]
    return auth


def dispatch(event: dict, ctx: Context) -> dict:
    """Main dispatch: API / EventBridge / Scheduler."""

    # --- Scheduler branch (nightly sweep) ---
    if event.get("source") == "scheduler" or event.get("action") == "sweep":
        result = ctx.sweep.run()
        return _resp(200, result)

    # --- EventBridge branch (group lifecycle) ---
    detail_type = event.get("detail-type") or event.get("type")
    if detail_type in CONSUMED_EVENT_TYPES:
        envelope = event.get("detail") or event
        ctx.consumer.handle(envelope)
        return _resp(200, {"status": "processed"})

    # --- API branch ---
    method = event.get("httpMethod", "GET")
    path = event.get("path", "/")
    set_correlation_id((event.get("headers") or {}).get("X-Correlation-Id"))

    op, params = _match(method, path)
    if op is None:
        return _resp(404, {"code": "NOT_FOUND", "message": "Resource not found."})

    body = {}
    if event.get("body"):
        try:
            body = json.loads(event["body"])
        except (ValueError, TypeError):
            return _resp(400, {"code": "VALIDATION_ERROR", "message": "Invalid JSON body."})

    try:
        principal = _principal(event)
        if principal is None:
            return _resp(401, {"code": "UNAUTHORIZED", "message": "Authentication required."})
        require_not_admin(principal)
        qs = event.get("queryStringParameters") or {}
        claims = extract_claims(event)
        return _execute(ctx, op, params, body, qs, principal, event, claims)
    except AppError as err:
        return _resp(err.status, {"code": err.code, "message": err.message,
                                  **({"details": err.details} if err.details else {})})


def _execute(ctx: Context, op: str, params: dict, body: dict, qs: dict,
             principal: Principal, event: dict, claims: dict) -> dict:
    token = _bearer_token(event)

    # member_group_ids are provided fresh by the edge claims authorizer on every
    # request (fresh-claims-at-the-edge), so no live membership refresh is needed.

    # --- Browse / Listings ---
    if op == "browseForums":
        return _browse_forums(ctx, principal, token)
    if op == "listPosts":
        return _list_posts(ctx, params["id"], qs, principal)
    if op == "getThread":
        return _get_thread(ctx, params["id"], qs, principal)
    if op == "listReplies":
        return _list_replies(ctx, params["id"], qs, principal)
    if op == "listFollows":
        return _list_follows(ctx, principal)

    # --- Forum/Channel management ---
    if op == "createForum":
        return _create_forum(ctx, body, principal)
    if op == "editForum":
        return _edit_forum(ctx, params["id"], body, principal)
    if op == "deleteForum":
        return _delete_forum(ctx, params["id"], principal)
    if op == "createChannel":
        return _create_channel(ctx, params["id"], body, principal)
    if op == "editChannel":
        return _edit_channel(ctx, params["id"], body, principal)
    if op == "deleteChannel":
        return _delete_channel(ctx, params["id"], principal)

    # --- Post CRUD ---
    if op == "createPost":
        return _create_post(ctx, params["id"], body, principal, token, claims)
    if op == "editPost":
        return _edit_post(ctx, params["id"], body, principal)
    if op == "deletePost":
        return _delete_post(ctx, params["id"], principal)

    # --- Reply CRUD ---
    if op == "createReply":
        return _create_reply(ctx, params["id"], body, principal, token, claims)
    if op == "editReply":
        return _edit_reply(ctx, params["id"], body, qs, principal)
    if op == "deleteReply":
        return _delete_reply(ctx, params["id"], qs, principal)

    # --- Reactions ---
    if op == "toggleReaction":
        return _toggle_reaction(ctx, params["id"], "post", body, principal)
    if op == "toggleReplyReaction":
        return _toggle_reaction(ctx, params["id"], "reply", body, principal)

    # --- Pin / Accept ---
    if op == "togglePin":
        return _toggle_pin(ctx, params["id"], principal)
    if op == "acceptAnswer":
        return _accept_answer(ctx, params["id"], body, principal)

    # --- Follow ---
    if op == "toggleFollowPost":
        return _toggle_follow(ctx, params["id"], "post", principal)
    if op == "toggleFollowChannel":
        return _toggle_follow(ctx, params["id"], "channel", principal)

    # --- Report / Moderation ---
    if op == "reportPost":
        return _report_content(ctx, params["id"], "post", body, principal)
    if op == "reportReply":
        return _report_content(ctx, params["id"], "reply", body, principal)
    if op == "moderationQueue":
        return _moderation_queue(ctx, qs, principal)
    if op == "dismissReport":
        return _dismiss_report(ctx, params["id"], principal)
    if op == "actionReport":
        return _action_report(ctx, params["id"], principal)

    # --- Mention / Search ---
    if op == "mentionSuggest":
        return _mention_suggest(ctx, qs, principal, token)
    if op == "searchForum":
        return _search(ctx, qs, principal, token)

    return _resp(501, {"code": "NOT_IMPLEMENTED", "message": "Not yet available."})


# --- Implementation functions ---

def _browse_forums(ctx: Context, principal: Principal, token: str | None = None) -> dict:
    group_ids = get_accessible_group_ids(principal)
    # principal.member_group_ids is fresh from the edge claims authorizer, so
    # get_accessible_group_ids already reflects current membership.
    items = []
    if group_ids is None:
        # CL: get all non-hidden forums via scan (acceptable at community scale)
        all_forums = []
        resp = ctx.repo._table.scan(
            FilterExpression="sk = :meta AND begins_with(pk, :fp)",
            ExpressionAttributeValues={":meta": "META", ":fp": "FORUM#"},
        )
        all_forums.extend([i for i in resp.get("Items", []) if not i.get("hidden")])
        while resp.get("LastEvaluatedKey"):
            resp = ctx.repo._table.scan(
                FilterExpression="sk = :meta AND begins_with(pk, :fp)",
                ExpressionAttributeValues={":meta": "META", ":fp": "FORUM#"},
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            all_forums.extend([i for i in resp.get("Items", []) if not i.get("hidden")])
        items = [serialize_forum(f) for f in all_forums]
    else:
        for gid in group_ids:
            forums = ctx.repo.browse_forums_by_group(gid)
            items.extend([serialize_forum(f) for f in forums])
    # Attach channels to each forum
    for forum in items:
        channels = ctx.repo.list_channels_by_group(forum["groupId"], forum["id"])
        forum["channels"] = [serialize_channel(c) for c in channels]
    return _resp(200, {"items": items, "count": len(items)})


def _list_posts(ctx: Context, channel_id: str, qs: dict, principal: Principal) -> dict:
    channel = ctx.repo.get_channel(channel_id)
    if not channel:
        return _resp(404, {"code": "NOT_FOUND", "message": "Channel not found."})
    require_group_access(principal, channel["groupId"])
    limit = min(int(qs.get("limit", "20")), 100)
    cursor = qs.get("cursor")
    sort = qs.get("sort", "newest")

    # For non-default sorts, fetch a larger batch to sort meaningfully
    # (at community scale this is bounded and acceptable)
    fetch_limit = limit if sort == "newest" else min(limit * 5, 500)
    posts, next_cursor = ctx.repo.list_posts_by_channel(channel_id, limit=fetch_limit, cursor=cursor)

    # Apply sort
    if sort == "active":
        posts.sort(key=lambda p: int(p.get("replyCount", 0)), reverse=True)
    elif sort == "reactions":
        posts.sort(key=lambda p: sum(int(v) for v in (p.get("reactionCounts") or {}).values()), reverse=True)
    elif sort == "unanswered":
        posts = [p for p in posts if not p.get("acceptedReplyId") and int(p.get("replyCount", 0)) == 0]

    # Pinned posts always first regardless of sort
    pinned = [p for p in posts if p.get("pinned")]
    regular = [p for p in posts if not p.get("pinned")]
    sorted_posts = pinned + regular

    # Trim to requested page size
    page = sorted_posts[:limit]
    items = [serialize_post(p) for p in page]
    return _resp(200, {"items": items, "count": len(items), "cursor": next_cursor})


def _get_thread(ctx: Context, post_id: str, qs: dict, principal: Principal) -> dict:
    post = ctx.repo.get_post(post_id)
    if not post:
        return _resp(404, {"code": "NOT_FOUND", "message": "Post not found."})
    require_group_access(principal, post["groupId"])
    # Caller's reaction
    reaction = ctx.repo.get_reaction(f"POST#{post_id}", principal.user_id)
    caller_reaction = reaction.get("kind") if reaction else None
    limit = min(int(qs.get("limit", "50")), 100)
    cursor = qs.get("cursor")
    replies, next_cursor = ctx.repo.list_replies_by_post(post_id, limit=limit, cursor=cursor)
    reply_items = []
    for r in replies:
        r_reaction = ctx.repo.get_reaction(f"POST#{post_id}", principal.user_id)
        # Per-REPLY flags, not the post's: the caller may own the post and none
        # of the replies, or one reply out of many. Evaluating this once for the
        # thread is what put a Delete button on other members' replies.
        reply_items.append(serialize_reply(r, can_edit=can_edit(principal, r),
                                           can_delete=can_delete(principal, r)))
    is_author = principal.user_id == post.get("authorId")
    can_accept = is_author or principal.role in ("CommunityLeader", "UserGroupLeader")
    # No self-reaction (a member cannot react to their own post).
    can_react = not is_author
    return _resp(200, {
        "post": serialize_post(post, caller_reaction, can_accept=can_accept,
                               can_react=can_react,
                               can_edit=can_edit(principal, post),
                               can_delete=can_delete(principal, post)),
        "replies": {"items": reply_items, "count": len(reply_items), "cursor": next_cursor},
    })


def _list_replies(ctx: Context, post_id: str, qs: dict, principal: Principal) -> dict:
    post = ctx.repo.get_post(post_id)
    if not post:
        return _resp(404, {"code": "NOT_FOUND", "message": "Post not found."})
    require_group_access(principal, post["groupId"])
    limit = min(int(qs.get("limit", "50")), 100)
    cursor = qs.get("cursor")
    replies, next_cursor = ctx.repo.list_replies_by_post(post_id, limit=limit, cursor=cursor)
    items = [serialize_reply(r, can_edit=can_edit(principal, r),
                             can_delete=can_delete(principal, r)) for r in replies]
    return _resp(200, {"items": items, "count": len(items), "cursor": next_cursor})


def _list_follows(ctx: Context, principal: Principal) -> dict:
    follows = ctx.repo.query_follows_for_user(principal.user_id)
    items = [serialize_follow(f) for f in follows]
    return _resp(200, {"items": items, "count": len(items)})


def _create_forum(ctx: Context, body: dict, principal: Principal) -> dict:
    from _conventions.validation import require_str
    name = require_str(body.get("name"), "name", max_len=100)
    group_id = require_str(body.get("groupId"), "groupId", max_len=100)
    # Only CL can create forums (UG forums auto-created on group creation)
    require_forum_create(principal)
    import uuid
    forum_id = str(uuid.uuid4())
    forum = {
        "forumId": forum_id, "groupId": group_id, "name": name,
        "description": body.get("description", ""),
        "createdBy": principal.user_id, "createdAt": now_iso(),
        "hidden": False, "channelCount": 1,
    }
    ctx.repo.put_forum(forum)
    # Auto-create "General" channel (BR-6)
    channel_id = str(uuid.uuid4())
    channel = {
        "channelId": channel_id, "forumId": forum_id, "groupId": group_id,
        "name": "General", "description": "", "postCount": 0,
        "lastActivityAt": now_iso(), "createdBy": principal.user_id, "createdAt": now_iso(),
        "hidden": False,
    }
    ctx.repo.put_channel(channel)
    result = serialize_forum(forum)
    result["channels"] = [serialize_channel(channel)]
    return _resp(201, result)


def _edit_forum(ctx: Context, forum_id: str, body: dict, principal: Principal) -> dict:
    forum = ctx.repo.get_forum(forum_id)
    if not forum:
        return _resp(404, {"code": "NOT_FOUND", "message": "Forum not found."})
    require_manage(principal, forum["groupId"])
    updates = {}
    if "name" in body:
        from _conventions.validation import require_str
        updates["name"] = require_str(body["name"], "name", max_len=100)
    if "description" in body:
        updates["description"] = body["description"][:500] if body["description"] else ""
    if updates:
        forum = ctx.repo.update_forum(forum_id, updates)
    return _resp(200, serialize_forum(forum))


def _delete_forum(ctx: Context, forum_id: str, principal: Principal) -> dict:
    forum = ctx.repo.get_forum(forum_id)
    if not forum:
        return _resp(404, {"code": "NOT_FOUND", "message": "Forum not found."})
    require_manage(principal, forum["groupId"])
    # Mark as PURGING (immediate hide); sweep will purge rows
    ctx.repo.mark_forum_purging(forum_id)
    ctx.events.forum_channel_deleted(forum_id, forum_id, forum["groupId"], principal.user_id)
    return _resp(204, None)


def _create_channel(ctx: Context, forum_id: str, body: dict, principal: Principal) -> dict:
    from _conventions.validation import require_str
    forum = ctx.repo.get_forum(forum_id)
    if not forum:
        return _resp(404, {"code": "NOT_FOUND", "message": "Forum not found."})
    require_manage(principal, forum["groupId"])
    name = require_str(body.get("name"), "name", max_len=100)
    import uuid
    channel_id = str(uuid.uuid4())
    channel = {
        "channelId": channel_id, "forumId": forum_id, "groupId": forum["groupId"],
        "name": name, "description": body.get("description", ""),
        "postCount": 0, "lastActivityAt": now_iso(),
        "createdBy": principal.user_id, "createdAt": now_iso(), "hidden": False,
    }
    ctx.repo.put_channel(channel)
    ctx.repo.increment_channel_count(forum_id, 1)
    return _resp(201, serialize_channel(channel))


def _edit_channel(ctx: Context, channel_id: str, body: dict, principal: Principal) -> dict:
    channel = ctx.repo.get_channel(channel_id)
    if not channel:
        return _resp(404, {"code": "NOT_FOUND", "message": "Channel not found."})
    require_manage(principal, channel["groupId"])
    updates = {}
    if "name" in body:
        from _conventions.validation import require_str
        updates["name"] = require_str(body["name"], "name", max_len=100)
    if "description" in body:
        updates["description"] = body["description"][:500] if body["description"] else ""
    if updates:
        updates["updatedAt"] = now_iso()
        # Direct update on channel META
        expr_parts, values, names = [], {}, {}
        for i, (k, v) in enumerate(updates.items()):
            attr = f"#a{i}"; val = f":v{i}"
            expr_parts.append(f"{attr} = {val}")
            names[attr] = k; values[val] = v
        from repository import _decimalize
        ctx.repo._table.update_item(
            Key={"pk": f"CHANNEL#{channel_id}", "sk": "META"},
            UpdateExpression="SET " + ", ".join(expr_parts),
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=_decimalize(values),
        )
        channel.update(updates)
    return _resp(200, serialize_channel(channel))


def _delete_channel(ctx: Context, channel_id: str, principal: Principal) -> dict:
    channel = ctx.repo.get_channel(channel_id)
    if not channel:
        return _resp(404, {"code": "NOT_FOUND", "message": "Channel not found."})
    require_manage(principal, channel["groupId"])
    # Mark channel hidden (sweep will clean); decrement forum channelCount
    ctx.repo.delete_item(f"CHANNEL#{channel_id}", "META")
    ctx.repo.increment_channel_count(channel["forumId"], -1)
    ctx.events.forum_channel_deleted(channel_id, channel["forumId"], channel["groupId"], principal.user_id)
    return _resp(204, None)


def _create_post(ctx: Context, channel_id: str, body: dict, principal: Principal, token: str | None, claims: dict) -> dict:
    channel = ctx.repo.get_channel(channel_id)
    if not channel:
        return _resp(404, {"code": "NOT_FOUND", "message": "Channel not found."})
    require_group_access(principal, channel["groupId"])
    # Rate limit
    if not ctx.repo.check_rate(principal.user_id, "post", RATE_LIMIT_POST_PER_HOUR):
        return _resp(429, {"code": "RATE_LIMITED", "message": "Post rate limit exceeded."})
    validated = validate_post_input(body)
    sanitized_body = sanitize_markdown(validated["body"])
    # Tokenize for search index
    terms = tokenize(validated["title"], sanitized_body)
    import uuid
    post_id = str(uuid.uuid4())
    ts = now_iso()
    post = {
        "postId": post_id, "channelId": channel_id, "forumId": channel["forumId"],
        "groupId": channel["groupId"], "authorId": principal.user_id,
        "authorName": _author_name(principal, claims), "authorRoleLabel": _role_label(principal),
        "title": validated["title"], "body": sanitized_body,
        "tags": validated["tags"], "pinned": False, "pinnedAt": None,
        "acceptedReplyId": None, "edited": False, "editedAt": None,
        "replyCount": 0, "reactionCounts": {}, "createdAt": ts, "deleted": False,
    }
    from models import gsi3_term_items
    term_items = gsi3_term_items(post_id, terms)
    ctx.repo.create_post_transact(post, term_items, channel_id)
    ctx.repo.increment_rate(principal.user_id, "post")
    # Mentions
    valid_mentions = []
    if validated["mentions"]:
        valid_mentions = ctx.mentions.validate_mentions(validated["mentions"], channel["groupId"], token,
                                                        claim_headers=claims_to_headers(principal))
        for uid in valid_mentions:
            ctx.events.member_mentioned(uid, principal.user_id, _author_name(principal, claims), post_id, channel["groupId"], "post")
    # Channel followers for notification
    channel_followers = ctx.repo.query_follows_for_target(f"CHANNEL#{channel_id}")
    follower_ids = [f["userId"] for f in channel_followers if f["userId"] != principal.user_id]
    ctx.events.forum_post_created(post, follower_ids)
    return _resp(201, serialize_post(post, can_edit=can_edit(principal, post),
                                     can_delete=can_delete(principal, post)))


def _edit_post(ctx: Context, post_id: str, body: dict, principal: Principal) -> dict:
    post = ctx.repo.get_post(post_id)
    if not post:
        return _resp(404, {"code": "NOT_FOUND", "message": "Post not found."})
    require_group_access(principal, post["groupId"])
    require_author_or_leader(principal, post, edit_only=True)
    updates = {"edited": True, "editedAt": now_iso()}
    if "title" in body:
        from _conventions.validation import require_str
        updates["title"] = require_str(body["title"], "title", max_len=200)
    if "body" in body:
        updates["body"] = sanitize_markdown(body["body"])
    if "tags" in body:
        updates["tags"] = body["tags"][:5] if body["tags"] else []
    post = ctx.repo.update_post(post_id, updates)
    return _resp(200, serialize_post(post, can_edit=can_edit(principal, post),
                                     can_delete=can_delete(principal, post)))


def _delete_post(ctx: Context, post_id: str, principal: Principal) -> dict:
    post = ctx.repo.get_post(post_id)
    if not post:
        return _resp(404, {"code": "NOT_FOUND", "message": "Post not found."})
    require_group_access(principal, post["groupId"])
    require_author_or_leader(principal, post, edit_only=False)
    ctx.repo.update_post(post_id, {"deleted": True})
    ctx.events.post_deleted(post_id, post["groupId"], principal.user_id)
    return _resp(204, None)


def _create_reply(ctx: Context, post_id: str, body: dict, principal: Principal, token: str | None, claims: dict) -> dict:
    post = ctx.repo.get_post(post_id)
    if not post:
        return _resp(404, {"code": "NOT_FOUND", "message": "Post not found."})
    require_group_access(principal, post["groupId"])
    if not ctx.repo.check_rate(principal.user_id, "reply", RATE_LIMIT_REPLY_PER_HOUR):
        return _resp(429, {"code": "RATE_LIMITED", "message": "Reply rate limit exceeded."})
    validated = validate_reply_input(body)
    sanitized_body = sanitize_markdown(validated["body"])
    import uuid
    reply_id = str(uuid.uuid4())
    ts = now_iso()
    reply = {
        "replyId": reply_id, "postId": post_id, "channelId": post["channelId"],
        "groupId": post["groupId"], "authorId": principal.user_id,
        "authorName": _author_name(principal, claims), "authorRoleLabel": _role_label(principal),
        "body": sanitized_body, "accepted": False, "edited": False, "editedAt": None,
        "reactionCounts": {}, "createdAt": ts,
    }
    ctx.repo.create_reply_transact(reply, post_id, post["channelId"])
    ctx.repo.increment_rate(principal.user_id, "reply")
    # Mentions
    if validated["mentions"]:
        valid_mentions = ctx.mentions.validate_mentions(validated["mentions"], post["groupId"], token,
                                                        claim_headers=claims_to_headers(principal))
        for uid in valid_mentions:
            ctx.events.member_mentioned(uid, principal.user_id, _author_name(principal, claims), post_id, post["groupId"], "reply")
    # Post followers for notification
    post_followers = ctx.repo.query_follows_for_target(f"POST#{post_id}")
    follower_ids = [f["userId"] for f in post_followers if f["userId"] != principal.user_id]
    ctx.events.forum_reply_created(reply, post, follower_ids)
    return _resp(201, serialize_reply(reply, can_edit=can_edit(principal, reply),
                                      can_delete=can_delete(principal, reply)))


def _resolve_reply(ctx: Context, reply_id: str, qs: dict,
                   principal: Principal) -> tuple[dict | None, dict | None, dict | None]:
    """Locate a reply from its id plus the postId the caller supplies.

    Replies live at POST#{postId} / REPLY#{replyId}, so a reply id alone does not
    address the item. Both operations below used to return 501 for that reason,
    with a TODO proposing a REPLY#->POST# pointer item written at create time.
    That is unnecessary: the postId is already on every serialized reply, so the
    client always has it, and it needs no pointer and no backfill of existing
    replies.

    Taking it from the caller is safe because the reply is read UNDER the supplied
    post — a forged or mismatched postId finds nothing and 404s, so this cannot be
    used to reach a reply in a group the caller cannot see. Group access is
    checked against the post before the reply is touched.

    Returns (post, reply, error_response); exactly one of reply/error is set.
    """
    post_id = (qs.get("postId") or "").strip()
    if not post_id:
        return None, None, _resp(400, {
            "code": "VALIDATION_ERROR",
            "message": "postId is required to address a reply."})
    post = ctx.repo.get_post(post_id)
    if not post or post.get("deleted"):
        return None, None, _resp(404, {"code": "NOT_FOUND", "message": "Reply not found."})
    require_group_access(principal, post["groupId"])
    reply = ctx.repo.get_reply(post_id, reply_id)
    if not reply or reply.get("deleted"):
        # Same 404 for "no such reply" and "not under that post" (BR-A8 style):
        # never confirm existence to someone who guessed the wrong parent.
        return None, None, _resp(404, {"code": "NOT_FOUND", "message": "Reply not found."})
    return post, reply, None


def _edit_reply(ctx: Context, reply_id: str, body: dict, qs: dict, principal: Principal) -> dict:
    post, reply, err = _resolve_reply(ctx, reply_id, qs, principal)
    if err:
        return err
    # BR-5: edit is AUTHOR ONLY — a leader may delete but never reword.
    require_author_or_leader(principal, reply, edit_only=True)
    validated = validate_reply_input(body)
    updated = ctx.repo.update_reply(post["postId"], reply_id, {
        "body": sanitize_markdown(validated["body"]),
        "edited": True,
        "editedAt": now_iso(),
    })
    return _resp(200, serialize_reply(updated, can_edit=can_edit(principal, updated),
                                      can_delete=can_delete(principal, updated)))


def _delete_reply(ctx: Context, reply_id: str, qs: dict, principal: Principal) -> dict:
    post, reply, err = _resolve_reply(ctx, reply_id, qs, principal)
    if err:
        return err
    # BR-5: author OR leader in scope.
    require_author_or_leader(principal, reply, edit_only=False)
    # Soft delete, matching _delete_post, so moderation history survives.
    # Clearing acceptedReplyId matters: leaving it pointing at a deleted reply
    # would keep the post badged as answered with no visible answer.
    ctx.repo.soft_delete_reply(
        post["postId"], reply_id,
        was_accepted=post.get("acceptedReplyId") == reply_id)
    return _resp(204, None)


def _toggle_reaction(ctx: Context, target_id: str, target_type: str, body: dict, principal: Principal) -> dict:
    kind = validate_reaction_kind(body.get("kind", ""))
    # Resolve target
    if target_type == "post":
        target = ctx.repo.get_post(target_id)
        target_pk = f"POST#{target_id}"
        target_sk = "META"
    else:
        # Reply reaction — need postId context
        return _resp(501, {"code": "NOT_IMPLEMENTED", "message": "Reply reaction requires context."})
    if not target:
        return _resp(404, {"code": "NOT_FOUND", "message": "Target not found."})
    require_group_access(principal, target["groupId"])
    # A member cannot react to their own post (defense-in-depth; the UI also
    # hides the button via the post's canReact flag).
    if principal.user_id == target.get("authorId"):
        return _resp(403, {"code": "FORBIDDEN",
                           "message": "You cannot react to your own post."})
    # Get existing reaction
    existing = ctx.repo.get_reaction(target_pk, principal.user_id)
    old_kind = existing.get("kind") if existing else None
    new_kind = None if kind == "clear" or kind == old_kind else kind
    if new_kind == old_kind and old_kind is None:
        return _resp(200, {"status": "no_change"})
    ctx.repo.set_reaction_transact(target_pk, target_sk, principal.user_id, new_kind, old_kind)
    return _resp(200, {"status": "updated", "kind": new_kind})


def _toggle_pin(ctx: Context, post_id: str, principal: Principal) -> dict:
    post = ctx.repo.get_post(post_id)
    if not post:
        return _resp(404, {"code": "NOT_FOUND", "message": "Post not found."})
    require_pin_or_accept(principal, post["groupId"])
    pinned = not post.get("pinned", False)
    updates = {"pinned": pinned, "pinnedAt": now_iso() if pinned else None}
    ctx.repo.update_post(post_id, updates)
    return _resp(200, {"pinned": pinned})


def _accept_answer(ctx: Context, post_id: str, body: dict, principal: Principal) -> dict:
    post = ctx.repo.get_post(post_id)
    if not post:
        return _resp(404, {"code": "NOT_FOUND", "message": "Post not found."})
    require_group_access(principal, post["groupId"])
    # Author OR leader can accept (BR-15)
    if principal.user_id != post.get("authorId"):
        require_pin_or_accept(principal, post["groupId"])
    reply_id = body.get("replyId")
    old_accepted = post.get("acceptedReplyId")
    # Clear previous
    if old_accepted and old_accepted != reply_id:
        ctx.repo.update_reply(post_id, old_accepted, {"accepted": False})
        old_reply = ctx.repo.get_reply(post_id, old_accepted)
        if old_reply:
            ctx.events.reply_accepted(old_reply, False)
    # Set new
    if reply_id:
        ctx.repo.update_reply(post_id, reply_id, {"accepted": True})
        new_reply = ctx.repo.get_reply(post_id, reply_id)
        if new_reply:
            ctx.events.reply_accepted(new_reply, True)
    ctx.repo.update_post(post_id, {"acceptedReplyId": reply_id})
    return _resp(200, {"acceptedReplyId": reply_id})


def _toggle_follow(ctx: Context, target_id: str, target_type: str, principal: Principal) -> dict:
    target_pk = f"POST#{target_id}" if target_type == "post" else f"CHANNEL#{target_id}"
    # Check access
    if target_type == "post":
        target = ctx.repo.get_post(target_id)
    else:
        target = ctx.repo.get_channel(target_id)
    if not target:
        return _resp(404, {"code": "NOT_FOUND", "message": "Target not found."})
    require_group_access(principal, target["groupId"])
    # Toggle
    existing = ctx.repo.get_follow(target_pk, principal.user_id)
    if existing:
        ctx.repo.delete_follow(target_pk, principal.user_id)
        return _resp(200, {"following": False})
    else:
        name = target.get("title", target.get("name", ""))
        ctx.repo.put_follow(target_pk, principal.user_id, target_id, target_type, name)
        return _resp(200, {"following": True})


def _report_content(ctx: Context, target_id: str, target_type: str, body: dict, principal: Principal) -> dict:
    # Resolve target to get groupId
    if target_type == "post":
        target = ctx.repo.get_post(target_id)
    else:
        return _resp(501, {"code": "NOT_IMPLEMENTED", "message": "Reply reporting requires context."})
    if not target:
        return _resp(404, {"code": "NOT_FOUND", "message": "Target not found."})
    require_group_access(principal, target["groupId"])
    # Dedupe check
    if not ctx.repo.put_report_dedupe(principal.user_id, target_id):
        return _resp(409, {"code": "ALREADY_REPORTED", "message": "You have already reported this content."})
    import uuid
    report_id = str(uuid.uuid4())
    report = {
        "reportId": report_id, "targetId": target_id, "targetType": target_type,
        "groupId": target["groupId"], "reporterId": principal.user_id,
        "reason": (body.get("reason") or "")[:500], "status": "Open",
        "createdAt": now_iso(), "resolvedAt": None, "resolvedBy": None,
    }
    ctx.repo.put_report(report)
    ctx.events.post_reported(report)
    return _resp(200, {"reportId": report_id})


def _moderation_queue(ctx: Context, qs: dict, principal: Principal) -> dict:
    require_moderation(principal)
    limit = min(int(qs.get("limit", "20")), 100)
    cursor = qs.get("cursor")
    # CL: all groups; UGL: own group
    if principal.role == "CommunityLeader":
        # For CL, we'd need to query across all groups or use a different approach
        # At community scale, query each group and merge (few groups)
        # Simplified: scan GSI4 for all REPORTGROUP# partitions
        items = []
        resp = ctx.repo._table.query(
            IndexName="GSI4",
            KeyConditionExpression="begins_with(gsi4pk, :prefix)",
            ExpressionAttributeValues={":prefix": "REPORTGROUP#"},
        ) if False else {"Items": []}  # GSI4 needs exact PK; use scan for CL
        # Actually for CL with all-group access, scan filtered
        scan_resp = ctx.repo._table.scan(
            FilterExpression="#s = :open AND begins_with(pk, :rp)",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":open": "Open", ":rp": "REPORT#"},
            Limit=limit,
        )
        items = [serialize_report(r) for r in scan_resp.get("Items", [])]
        return _resp(200, {"items": items, "count": len(items), "cursor": None})
    else:
        # UGL: own group
        reports, next_cursor = ctx.repo.list_reports_by_group(principal.led_group_id or "", limit=limit, cursor=cursor)
        items = [serialize_report(r) for r in reports]
        return _resp(200, {"items": items, "count": len(items), "cursor": next_cursor})


def _dismiss_report(ctx: Context, report_id: str, principal: Principal) -> dict:
    report = ctx.repo.get_report(report_id)
    if not report:
        return _resp(404, {"code": "NOT_FOUND", "message": "Report not found."})
    require_moderation(principal, report.get("groupId"))
    ctx.repo.update_report_status(report_id, "Dismissed", principal.user_id)
    # Clean dedupe so reporter can re-report if needed
    ctx.repo.delete_report_dedupe(report.get("reporterId", ""), report.get("targetId", ""))
    return _resp(200, {"status": "Dismissed"})


def _action_report(ctx: Context, report_id: str, principal: Principal) -> dict:
    report = ctx.repo.get_report(report_id)
    if not report:
        return _resp(404, {"code": "NOT_FOUND", "message": "Report not found."})
    require_moderation(principal, report.get("groupId"))
    # Delete the reported content
    target_id = report.get("targetId", "")
    if report.get("targetType") == "post":
        ctx.repo.update_post(target_id, {"deleted": True})
        ctx.events.post_deleted(target_id, report.get("groupId", ""), principal.user_id)
    ctx.repo.update_report_status(report_id, "Actioned", principal.user_id)
    return _resp(200, {"status": "Actioned"})


def _mention_suggest(ctx: Context, qs: dict, principal: Principal, token: str | None) -> dict:
    q = qs.get("q", "")
    group_id = qs.get("groupId", "")
    if not q or not group_id:
        return _resp(200, {"items": [], "count": 0})
    require_group_access(principal, group_id)
    candidates = ctx.mentions.suggest(q, group_id, token,
                                      claim_headers=claims_to_headers(principal))
    return _resp(200, {"items": candidates, "count": len(candidates)})


def _search(ctx: Context, qs: dict, principal: Principal, token: str | None = None) -> dict:
    """Keyword search over the GSI3 inverted index (W12, BR-29, DV-2).

    Order of operations matters here and used to be wrong: the match set was
    truncated to `limit` BEFORE the access-scope and deleted/hidden filters ran,
    so a caller could be handed an arbitrary 20 ids, have most of them filtered
    away, and see a near-empty result while hundreds of visible matches existed.
    Filter first, rank, then slice.

    The slice source was also a `set`, whose iteration order is arbitrary — the
    same query returned a different 20 posts run to run and never the newest.
    Results are now ordered newest-first, which is both stable and what the
    channel/forum listings already do.
    """
    from models import SEARCH_QUERY_TERM_CAP, _extract_terms
    q = qs.get("q", "")
    if not q or len(q) < 2:
        return _resp(200, {"items": [], "count": 0})
    terms = _extract_terms(q)
    if not terms:
        return _resp(200, {"items": [], "count": 0})
    # Query each term and intersect (AND semantics: a hit contains every word).
    matched_ids: set[str] | None = None
    for term in terms[:SEARCH_QUERY_TERM_CAP]:
        term_ids = set(ctx.repo.query_term(term))
        if not term_ids:
            return _resp(200, {"items": [], "count": 0})
        matched_ids = term_ids if matched_ids is None else (matched_ids & term_ids)
        if not matched_ids:
            return _resp(200, {"items": [], "count": 0})
    if not matched_ids:
        return _resp(200, {"items": [], "count": 0})

    posts = ctx.repo.batch_get_posts(list(matched_ids))

    # Access-scope filter — member_group_ids are fresh from the edge claims authorizer.
    accessible_groups = get_accessible_group_ids(principal)
    if accessible_groups is not None:
        accessible_set = set(accessible_groups)
        posts = [p for p in posts if p.get("groupId") in accessible_set]
    # Filter hidden/deleted
    posts = [p for p in posts if not p.get("deleted") and not p.get("hidden")]

    # Optional narrowing filters (declared in the OpenAPI contract; previously
    # accepted and silently ignored, so "search this channel" searched the whole
    # forum estate). Applied after the access filter so they can only ever
    # narrow what the caller is already allowed to see.
    for field, key in (("groupId", "groupId"), ("forumId", "forumId"),
                       ("channelId", "channelId")):
        wanted = qs.get(key)
        if wanted:
            posts = [p for p in posts if p.get(field) == wanted]

    total = len(posts)
    posts.sort(key=lambda p: str(p.get("createdAt") or ""), reverse=True)
    limit = min(int(qs.get("limit", "20")), 50)
    page = posts[:limit]
    items = [serialize_post(p) for p in page]
    # `count` is the page size (unchanged contract); `total` lets the UI say
    # "showing 20 of 215" instead of implying 20 is all there is.
    return _resp(200, {"items": items, "count": len(items), "total": total})


# --- Helpers ---

def _author_name(principal: Principal, claims: dict | None = None) -> str:
    """Extract display name from JWT claims (ND-4=A).
    
    Cognito authorizer passes given_name, family_name, email in claims.
    Fail-closed to email or user_id if no name claims present.
    """
    if claims:
        given = claims.get("given_name", "")
        family = claims.get("family_name", "")
        if given or family:
            return f"{given} {family}".strip()
        email = claims.get("email", "")
        if email:
            return email.split("@")[0]  # user part of email as fallback
    return principal.user_id


def _role_label(principal: Principal) -> str:
    """Map role to display label."""
    labels = {
        "CommunityLeader": "Community Leader",
        "UserGroupLeader": "User Group Leader",
        "Member": "Member",
    }
    return labels.get(principal.role, principal.role)


@global_handler
def handler(event, context):
    try:
        ctx = Context()
        return dispatch(event, ctx)
    except AppError as err:
        return to_response(err)
