"""Benign classroom comment resolver: download and print one text flag only."""
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

VIDEO = '4ok4e0Jvy_4'
FLAG_URL = 'https://gist.githubusercontent.com/danafaye/8100c9037cdd799741c405d7b34a37f2/raw/710fef32e945a23fe1482de52dd446e54d1de7d8/newbie_notes.txt'
RESOURCE_ROOT = 'https://gist.githubusercontent.com/danafaye/8100c9037cdd799741c405d7b34a37f2/raw/710fef32e945a23fe1482de52dd446e54d1de7d8/'

def comment_locator(text):
    sentences = [s.strip() for s in re.split(r'[.!?]+(?:\s+|$)', text.strip()) if s.strip()]
    if len(sentences) != 6 or any(not re.match(r'[A-Za-z]', s) for s in sentences):
        return None
    reference = ''.join(s[0].upper() for s in sentences)
    if reference != 'NEWBIE':
        return None
    url = RESOURCE_ROOT + reference.lower() + '_notes.txt'
    if url != FLAG_URL:
        raise ValueError('Unexpected classroom resource')
    return url

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def read_bounded(stream, limit):
    body = stream.read(limit + 1)
    if len(body) > limit:
        raise ValueError('Response exceeds classroom size limit')
    return body

def extract(page, pinned_id=None):
    if not isinstance(page, dict) or 'error' in page:
        raise ValueError('Invalid comments response')
    items = page.get('items', [])
    if not isinstance(items, list):
        raise ValueError('Invalid comment list')
    found = []
    for item in items:
        snippet = item.get('snippet', {})
        if snippet.get('videoId') != VIDEO:
            continue
        comment = snippet.get('topLevelComment', {})
        cid = comment.get('id', '')
        if pinned_id and cid != pinned_id:
            continue
        text = comment.get('snippet', {}).get('textDisplay', '')
        if not isinstance(text, str):
            continue
        url = comment_locator(text)
        if url:
            found.append((cid, url))
    if len(found) > 1:
        raise ValueError('Ambiguous lab references; pin the intended comment ID')
    return found

def validate_flag(body):
    flag = body.decode('ascii').strip()
    if not re.fullmatch(r'GF\{[A-Z0-9_]{1,100}\}', flag):
        raise ValueError('Downloaded file is not a classroom text flag')
    return flag

WATCH_URL = 'https://www.youtube.com/watch?v=' + VIDEO + '&hl=en'
BROWSER_NEXT = 'https://www.youtube.com/youtubei/v1/next?prettyPrint=false'
MAX_PAGES = 6

def fetch(url, limit, data=None, headers=None):
    base = {'User-Agent':'Mozilla/5.0', 'Accept-Language':'en-US,en;q=0.9'}
    base.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=base)
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(req, timeout=10) as response:
        return read_bounded(response, limit)

def walk(value):
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            yield item
            pending.extend(reversed(list(item.values())))
        elif isinstance(item, list):
            pending.extend(reversed(item))

def page_config(html):
    decoder = json.JSONDecoder()
    match = re.search(r'(?:var\s+)?ytInitialData\s*=\s*', html)
    if not match:
        raise ValueError('Public watch page has no initial data; consent or blocking may apply')
    initial = decoder.raw_decode(html[match.end():])[0]
    config = {}
    for match in re.finditer(r'ytcfg\.set\(\s*', html):
        try:
            item = decoder.raw_decode(html[match.end():])[0]
            if isinstance(item, dict):
                # Only browser context is retained. No credentials or API keys.
                for field in ('INNERTUBE_CONTEXT','INNERTUBE_CONTEXT_CLIENT_NAME','INNERTUBE_CLIENT_VERSION'):
                    if field in item: config[field] = item[field]
        except ValueError:
            continue
    context = config.get('INNERTUBE_CONTEXT')
    if not isinstance(context,dict) or not isinstance(context.get('client'),dict):
        raise ValueError('Public page has no usable browser context')
    if not isinstance(initial,dict):
        raise ValueError('Malformed public page data')
    return initial,config

def normalize_comments(response):
    items=[];seen=set()
    for node in walk(response):
        renderer=node.get('commentRenderer')
        if isinstance(renderer,dict):
            cid=renderer.get('commentId')
            content=renderer.get('contentText',{})
            text=content.get('simpleText') or ''.join(r.get('text','') for r in content.get('runs',[]))
        else:
            entity=node.get('commentEntityPayload')
            if not isinstance(entity,dict): continue
            properties=entity.get('properties',{})
            cid=properties.get('commentId')
            content=properties.get('content',{})
            text=content.get('content','') if isinstance(content,dict) else ''
        if not isinstance(cid,str) or not isinstance(text,str) or cid in seen: continue
        seen.add(cid)
        items.append({'snippet':{'videoId':VIDEO,'topLevelComment':{'id':cid,'snippet':{'textDisplay':text}}}})
    return {'items':items}

def continuations(root):
    tokens=[]
    for node in walk(root):
        item=node.get('continuationItemRenderer')
        if not isinstance(item,dict):continue
        command=item.get('continuationEndpoint',{}).get('continuationCommand',{})
        token=command.get('token')
        if isinstance(token,str) and 0<len(token)<=8192 and token not in tokens:tokens.append(token)
    return tokens

def comment_sections(initial):
    for node in walk(initial):
        section=node.get('itemSectionRenderer')
        if isinstance(section,dict) and section.get('sectionIdentifier')=='comment-item-section':
            yield section

def comment_actions(response):
    for node in walk(response):
        for name in ('appendContinuationItemsAction','reloadContinuationItemsCommand'):
            action=node.get(name)
            if isinstance(action,dict) and 'comment' in action.get('targetId',''):
                yield action.get('continuationItems',[])

def newest_token(response):
    for node in walk(response):
        header=node.get('commentsHeaderRenderer')
        if not isinstance(header,dict):continue
        items=header.get('sortMenu',{}).get('sortFilterSubMenuRenderer',{}).get('subMenuItems',[])
        for item in items:
            if 'newest' in item.get('title','').lower():
                token=item.get('serviceEndpoint',{}).get('continuationCommand',{}).get('token')
                if isinstance(token,str) and 0<len(token)<=8192:return token
    return None

def public_comments(fetcher=fetch):
    html=fetcher(WATCH_URL,4*1024*1024).decode('utf-8')
    initial,config=page_config(html)
    sections=list(comment_sections(initial))
    queue=[]
    for section in sections:
        normalized=normalize_comments(section)
        if normalized['items']:yield normalized
        queue.extend(t for t in continuations(section) if t not in queue)
    seen=set();sorted_newest=False
    headers={'Content-Type':'application/json','Origin':'https://www.youtube.com',
             'X-Youtube-Client-Name':str(config.get('INNERTUBE_CONTEXT_CLIENT_NAME',1)),
             'X-Youtube-Client-Version':str(config.get('INNERTUBE_CLIENT_VERSION') or
                                           config['INNERTUBE_CONTEXT']['client'].get('clientVersion',''))}
    for _ in range(MAX_PAGES):
        if not queue:break
        token=queue.pop(0)
        if token in seen:continue
        seen.add(token)
        payload=json.dumps({'context':config['INNERTUBE_CONTEXT'],'continuation':token}).encode()
        response=json.loads(fetcher(BROWSER_NEXT,2*1024*1024,payload,headers))
        if not isinstance(response,dict) or 'error' in response:
            raise ValueError('Public comment response rejected')
        normalized=normalize_comments(response)
        if normalized['items']:yield normalized
        newest=newest_token(response)
        if newest and not sorted_newest:
            queue=[newest];sorted_newest=True
        else:
            for action in comment_actions(response):
                for next_token in continuations(action):
                    if next_token not in seen and next_token not in queue:queue.append(next_token)

def resolve(fetcher=fetch):
    pinned=os.environ.get('GF_YOUTUBE_COMMENT_ID')
    fixture=os.environ.get('GF_YOUTUBE_FIXTURE')
    if fixture:
        with open(fixture,'rb') as stream:
            pages=[json.loads(read_bounded(stream,262144))]
    else:
        pages=public_comments(fetcher)
    for page in pages:
        matches=extract(page,pinned)
        if not matches:continue
        cid,url=matches[0]
        local_flag=os.environ.get('GF_FLAG_FIXTURE') if fixture else None
        if local_flag:
            with open(local_flag,'rb') as stream:body=read_bounded(stream,8192)
        else:
            body=fetcher(url,8192)
        flag=validate_flag(body)
        mode='Offline fixture' if fixture else 'Public YouTube page'
        print('[+] '+mode+': comment acrostic decoded; classroom text flag loaded.')
        print(flag)
        return True
    raise ValueError('Classroom comment not found within the bounded public-page scan')


def main():
    try:
        return 0 if resolve() else 1
    except urllib.error.HTTPError as error:
        print('[!] Classroom retrieval failed: HTTP status '+str(error.code), file=sys.stderr)
    except (OSError,ValueError,KeyError,TypeError,AttributeError) as error:
        # Report errors without printing arbitrary remote text.
        print('[!] Classroom retrieval failed ('+type(error).__name__+').',file=sys.stderr)
    return 1

if __name__ == '__main__':
    sys.exit(main())
