from copy import deepcopy
import ast
import pytest
from serverhub.development.autonomous import replace_python_constant, development_messages, SCHEMAS
from serverhub.development.config import DevelopmentError
from serverhub.ai.providers import ProviderConfig, estimate_prompt


def test_literal_edit_preserves_comments_and_unicode_offsets_without_execution():
    content='# VERSION = "ignore"\nLABEL = "æøå"; VERSION = "broken"\n'
    updated=replace_python_constant(content,'VERSION','0.23.0')
    assert updated=='# VERSION = "ignore"\nLABEL = "æøå"; VERSION = \'0.23.0\'\n'
    tree=ast.parse(replace_python_constant('VALUE = None\n','VALUE',"__import__('os').system('bad')"))
    assert isinstance(tree.body[0].value,ast.Constant)
    assert tree.body[0].value.value=="__import__('os').system('bad')"


def test_ambiguous_constants_fail_closed():
    with pytest.raises(DevelopmentError,match='exactly one'):
        replace_python_constant('VERSION=1\nVERSION=2\n','VERSION',3)
    with pytest.raises(DevelopmentError,match='literal bounds'):
        replace_python_constant('VALUE=1\n','VALUE',float('inf'))


def test_compaction_keeps_goal_and_complete_recent_tool_groups_without_losing_durable_history():
    config=ProviderConfig(kind='ollama',model='fixture',base_url='http://localhost',context_limit=8192,max_output_tokens=512)
    messages=[{'role':'system','content':'Immutable safety rules'},{'role':'user','content':'The original requested change'}]
    for index in range(12):
        identity=str(index)
        messages.extend([{'role':'assistant','content':'Reasoning '*200,'tool_calls':[{'id':identity,'type':'function','function':{'name':'read_file','arguments':'{"path":"app.py"}'}}]},
                         {'role':'tool','tool_call_id':identity,'content':'Observation '*400}])
    state={'messages':messages,'plan':['Inspect','Repair','Verify'],'completed_calls':{}}
    original=deepcopy(messages)
    result=development_messages(state,config,50000)
    assert result[:2]==messages[:2] and messages==original
    assert result[-1]['tool_call_id']=='11'
    calls={call['id'] for item in result for call in item.get('tool_calls',[])}
    assert all(item['tool_call_id'] in calls for item in result if item['role']=='tool')
    assert estimate_prompt(result,SCHEMAS,kind='ollama')['estimated_input_tokens']<8192-512
