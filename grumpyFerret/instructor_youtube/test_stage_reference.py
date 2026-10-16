import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('yt', ROOT/'instructor_youtube/youtube_stage.py')
yt=importlib.util.module_from_spec(spec);spec.loader.exec_module(yt)
fixture=json.loads((ROOT/'instructor_youtube/youtube_comments_fixture.json').read_text())
comment=(ROOT/'instructor_youtube/youtube_comment.txt').read_text().strip()
checks=[]
def check(name, condition):
    assert condition, name
    checks.append(name)
def rejects(name, func):
    try: func()
    except ValueError: checks.append(name)
    else: raise AssertionError(name)

check('Natural language draft contains no visible URL or marker',
      'http' not in comment and 'MM-LAB' not in comment)
check('Six sentence initials decode the intended resource',yt.comment_locator(comment)==yt.FLAG_URL)
check('Ordinary unrelated comments are ignored',yt.comment_locator('Thanks, very helpful!') is None)
check('Wrong acrostic does not select another URL',yt.comment_locator(comment.replace('Nice','Good',1)) is None)
check('Comment belongs to the configured video',len(yt.extract(fixture))==1)
wrong=json.loads(json.dumps(fixture));wrong['items'][0]['snippet']['videoId']='other-video'
check('Wrong video rejected',yt.extract(wrong)==[])
check('Pinned comment mismatch ignored',yt.extract(fixture,'different-comment')==[])
check('Pinned comment accepted',len(yt.extract(fixture,'CLASSROOM_FIXTURE_NOT_A_LIVE_COMMENT'))==1)
duplicate=json.loads(json.dumps(fixture));duplicate['items']*=2
rejects('Duplicate matching comments rejected',lambda:yt.extract(duplicate))
rejects('Malformed API response rejected',lambda:yt.extract({'items':None}))
rejects('API error document rejected',lambda:yt.extract({'error':{'code':403}}))
rejects('Oversized text response rejected',lambda:yt.read_bounded(io.BytesIO(b'x'*8193),8192))
rejects('Downloaded executable-looking data rejected',lambda:yt.validate_flag(b'MZ'+b'\0'*16))
rejects('Downloaded HTML rejected',lambda:yt.validate_flag(b'<html>not a flag</html>'))
rejects('Downloaded shell instructions rejected',lambda:yt.validate_flag(b'echo hello; id'))
check('Valid text flag accepted',yt.validate_flag((ROOT/'instructor_youtube/newbie_notes.txt').read_bytes()).startswith('GF{'))

calls=[]
def renderer(text=comment,cid='browser-comment'):
    return {'commentRenderer':{'commentId':cid,'contentText':{'runs':[{'text':text}]}}}
token={'continuationItemRenderer':{'continuationEndpoint':{'continuationCommand':{'token':'synthetic-first'}}}}
initial={'contents':{'itemSectionRenderer':{'sectionIdentifier':'comment-item-section','contents':[token]}}}
config={'INNERTUBE_CONTEXT':{'client':{'clientName':'WEB','clientVersion':'fixture-version'}},
        'INNERTUBE_CONTEXT_CLIENT_NAME':1,'INNERTUBE_CLIENT_VERSION':'fixture-version'}
html=('var ytInitialData = '+json.dumps(initial)+';ytcfg.set('+json.dumps(config)+');').encode()
reply={'onResponseReceivedEndpoints':[{'appendContinuationItemsAction':{'targetId':'comments-section','continuationItems':[renderer()]}}]}
def fake_fetch(url,limit,data=None,headers=None):
    calls.append((url,data))
    if url==yt.WATCH_URL:return html
    if url==yt.BROWSER_NEXT:
        payload=json.loads(data)
        assert payload['continuation']=='synthetic-first'
        assert 'key' not in payload and '?key=' not in url
        return json.dumps(reply).encode()
    assert url==yt.FLAG_URL
    return (ROOT/'instructor_youtube/newbie_notes.txt').read_bytes()
out=io.StringIO()
with patch.dict(os.environ,{},clear=True),contextlib.redirect_stdout(out):
    check('Browser loading sequence retrieves flag with an empty environment',yt.resolve(fake_fetch))
check('Only watch page, browser continuation and Gist requested',len(calls)==3 and calls[-1][0]==yt.FLAG_URL)
check('Public-page result identified distinctly from fixture output','Public YouTube page:' in out.getvalue())
modern={'frameworkUpdates':{'entityBatchUpdate':{'mutations':[{'payload':{'commentEntityPayload':{
    'properties':{'commentId':'modern-id','content':{'content':comment}}}}}]}}}
check('Modern entity comment schema normalized',len(yt.extract(yt.normalize_comments(modern)))==1)
check('Legacy renderer comment schema normalized',len(yt.extract(yt.normalize_comments(reply)))==1)
check('Unrelated text is not treated as a comment',yt.normalize_comments({'description':comment})['items']==[])
check('Repeated renderer ID deduplicated',len(yt.normalize_comments([renderer(),renderer()])['items'])==1)
parsed,cfg=yt.page_config(html.decode())
check('Initial JSON and dynamic browser context parsed',parsed==initial and cfg['INNERTUBE_CONTEXT']==config['INNERTUBE_CONTEXT'])
rejects('Consent or blocking page rejected without fabricated comments',lambda:yt.page_config('<html>Please sign in</html>'))
initial_extra={'contents':[initial,{'itemSectionRenderer':{'sectionIdentifier':'recommendations','contents':[token]}}]}
check('Non-comment page continuations excluded',len(list(yt.comment_sections(initial_extra)))==1)
menu={'commentsHeaderRenderer':{'sortMenu':{'sortFilterSubMenuRenderer':{'subMenuItems':[{
 'title':'Newest first','serviceEndpoint':{'continuationCommand':{'token':'newest-token'}}}]}}}}
check('Newest-first browser continuation selected',yt.newest_token(menu)=='newest-token')
source_stage=(ROOT/'instructor_youtube/youtube_stage.py').read_text()
check('No environment API-key dependency or Data API endpoint remains',
      'YOUTUBE_API_KEY' not in source_stage and 'googleapis.com/youtube' not in source_stage)

source=(ROOT/'grumpyferret.c').read_text()
def array(name):
    block=re.search(r'\b'+name+r'\[SERIAL_LEN\]\s*=\s*\{([^}]+)\}',source).group(1)
    return bytes(int(v,16) for v in re.findall(r'0x([0-9a-fA-F]+)',block))
magic,target=array('MAGIC'),array('TARGET')
serial=bytes(((v-i)&255)^magic[i] for i,v in enumerate(target)).decode()
runtime=os.environ.copy();runtime.update({'GF_OFFLINE':'1',
 'GF_YOUTUBE_FIXTURE':str(ROOT/'instructor_youtube/youtube_comments_fixture.json'),
 'GF_FLAG_FIXTURE':str(ROOT/'instructor_youtube/newbie_notes.txt')})
binary=ROOT/'grumpyferret'
run=subprocess.run([str(binary),serial],env=runtime,text=True,capture_output=True,timeout=15)
check('Compiled ELF executes embedded stage and retains valid serial path',run.returncode==0 and 'serial accepted' in run.stdout and 'Offline fixture:' in run.stdout and 'GF{YOUTUBE_COMMENT_TO_GITHUB_FLAG}' in run.stdout)
run=subprocess.run([str(binary),'wrong-serial'],env=runtime,text=True,capture_output=True,timeout=15)
check('Incorrect serial still rejected after comment stage',run.returncode==1 and 'incorrect serial' in run.stdout)
check('Raw GitHub URL is absent from stripped ELF strings',yt.FLAG_URL.encode() not in binary.read_bytes())
result={'status':'passed','check_count':len(checks),'checks':checks,
        'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
        'live_youtube':'see public_page_live_verification.json and native_live_verification.json',
        'api_key_required':False,
        'live_github':'not checked by this offline suite; see gist_download_verification.json',
        'flag_url':yt.FLAG_URL,
        'video_id':yt.VIDEO,'comment_encoding':'first letter of each of six sentences: NEWBIE'}
(ROOT/'instructor_youtube/youtube_validation.json').write_text(json.dumps(result,indent=2)+'\n')
print(str(len(checks))+' offline checks passed; public-page live verification is recorded separately.')
