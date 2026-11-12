import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from coding_agent import Agent, ContextFull, Model


class FakeModel:
    window = 32768
    budget = 27000
    temperature = 0.7

    def count(self, messages):
        return sum(len(message['content']) for message in messages) // 3


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / 'project'
        self.project.mkdir()
        self.logs = self.root / 'logs'
        self.logs.mkdir()
        self.agent = Agent(self.project, 'Fix a sample function', self.logs, FakeModel(),
                           checks=['python3 -m py_compile sample.py'])

    def sample(self, content='value = 1\n'):
        path = self.project / 'sample.py'
        path.write_text(content)
        return path

    def test_stale_edit_is_rejected_without_mutation(self):
        path = self.sample()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        path.write_text('value = 2\n')
        with self.assertRaisesRegex(ValueError, 'Stale'):
            self.agent.do_edit_lines(dict(path='sample.py', start=1, end=1,
                                          sha256=digest, content='value = 3'), 1)
        self.assertEqual(path.read_text(), 'value = 2\n')

    def test_line_edit_and_append_preserve_crlf(self):
        path = self.sample()
        path.write_bytes(b'value = 1\r\n')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.agent.do_edit_lines(dict(path='sample.py', start=2, end=1,
                                      sha256=digest, content='other = 2'), 1)
        self.assertEqual(path.read_bytes(), b'value = 1\r\nother = 2\r\n')

    def test_read_does_not_silently_cut_long_lines_or_forbid_rereads(self):
        self.sample('x = ' + repr('a' * 800) + '\n')
        first = self.agent.do_read({'path': 'sample.py'}, 1)
        self.assertIn('a' * 800, first)
        self.assertEqual(first, self.agent.do_read({'path': 'sample.py'}, 2))

    def test_fuzzy_edit_cannot_change_whitespace_sensitive_content(self):
        path = self.sample('value = "a  "\n')
        with self.assertRaises(ValueError):
            self.agent.do_edit(dict(path='sample.py', old='value = "a"', new='value = 2'), 1)
        self.assertEqual(path.read_text(), 'value = "a  "\n')

    def test_large_change_rejected(self):
        with self.assertRaises(ValueError):
            self.agent.do_create(dict(path='sample.py', content='x=1\n' * 101), 1)
        self.assertFalse((self.project / 'sample.py').exists())

    def test_optional_integer_types_are_validated(self):
        for value in [True, '100', 1.5]:
            raw = json.dumps(dict(why='Read source', action='read', args=dict(path='x', count=value)))
            self.assertIsNotNone(self.agent.parse(raw, 'stop')[3])

    def test_failed_check_and_arbitrary_shell_cannot_unlock_finish(self):
        self.sample('broken syntax!\n')
        self.agent.s['did_work'] = True
        self.agent.wrote('sample.py', 1)
        self.agent.dispatch('shell', {'command': 'ls'}, 2)
        self.agent.dispatch('verify', {}, 3)
        for step in [4, 5]:
            with self.assertRaisesRegex(ValueError, 'not verified'):
                self.agent.dispatch('finish', {'report': 'done'}, step)
        self.sample()
        self.agent.wrote('sample.py', 6)
        self.agent.dispatch('verify', {}, 7)
        self.agent.dispatch('finish', {'report': 'done'}, 8)
        self.assertEqual(self.agent.s['status'], 'finish')

    def test_pipeline_failure_and_shell_invalidation(self):
        self.sample()
        self.agent.dispatch('verify', {}, 1)
        result = self.agent.dispatch('shell', {'command': 'false | cat'}, 2)
        self.assertTrue(result.startswith('exit=1'))
        self.assertEqual(self.agent.s['verified_epoch'], -1)

    def test_compaction_survives_resume(self):
        for step in range(12):
            self.agent.add('assistant', json.dumps(dict(action='note', args={'text': 'old' * 100})), step=step)
            self.agent.add('user', 'result ' * 100, step=step)
        self.agent.s['note'] = 'remaining obligation'
        self.agent.compact(2)
        self.agent.save()
        restored = Agent(self.project, 'Fix a sample function', self.logs, FakeModel(), resume=True)
        self.assertEqual(restored.msgs, self.agent.msgs)
        self.assertEqual(len(restored.msgs), 5)
        self.assertEqual(restored.s['note'], 'remaining obligation')

    def test_interrupted_call_not_replayed(self):
        self.agent.add('assistant', json.dumps(dict(action='create', args={'path': 'sample.py', 'content': 'x=1'})))
        self.agent.save()
        restored = Agent(self.project, 'Fix a sample function', self.logs, FakeModel(), resume=True)
        self.assertEqual(restored.msgs[-1]['role'], 'user')
        self.assertFalse((self.project / 'sample.py').exists())
        self.assertTrue(restored.s['needs_check'])

    def test_blocked_allowed_before_work(self):
        self.agent.dispatch('blocked', {'reason': 'Required input is missing'}, 1)
        self.assertEqual(self.agent.s['status'], 'blocked')

    def test_secret_and_escape_paths(self):
        for path in ['../outside', '.env', '.git/config', '.aws/credentials', '.env/nested']:
            with self.assertRaises(ValueError):
                self.agent.resolve(path)

    def test_template_token_count(self):
        model = Model.__new__(Model)
        calls = []
        def call(path, body):
            calls.append((path, body))
            return {'prompt': 'TEMPLATE'} if path == '/apply-template' else {'tokens': [1, 2, 3]}
        model.call = call
        self.assertEqual(model.count([dict(role='user', content='hello')]), 35)
        self.assertEqual(calls[1][1]['content'], 'TEMPLATE')

    def test_context_overflow_retry_shrinks_actual_request(self):
        class OverflowModel(FakeModel):
            def __init__(self):
                self.sizes = []
            def generate(self, messages, temperature):
                self.sizes.append(self.count(messages))
                if len(self.sizes) == 1:
                    raise ContextFull('too long')
                return '{}', 'stop'
        model = OverflowModel()
        self.agent.model = model
        for step in range(12):
            self.agent.add('assistant', '{}', step=step)
            self.agent.add('user', 'data' * 500, step=step)
        self.agent.ask(0.7)
        self.assertLess(model.sizes[1], model.sizes[0])

    def test_scripted_agent_completes_create_verify_finish(self):
        class ScriptedModel(FakeModel):
            def __init__(self):
                self.actions = iter([
                    ('create', dict(path='sample.py', content='value = 1')),
                    ('verify', {}), ('finish', {'report': 'Completed'})])
            def generate(self, messages, temperature):
                action, args = next(self.actions)
                return json.dumps(dict(why='Next step', action=action, args=args)), 'stop'
        self.agent.model = ScriptedModel()
        self.assertIn('Completed', self.agent.run())
        self.assertEqual(self.agent.s['verification'][0]['exit'], 0)


if __name__ == '__main__':
    unittest.main()
