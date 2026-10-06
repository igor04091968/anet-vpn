#!/usr/bin/env python3
"""Local CLI checks: no authorized keys, no UDP session, no TUN or route edits."""
import hashlib,json,os,pathlib,subprocess,sys,tempfile
binary=str(pathlib.Path(sys.argv[1]).resolve())
base=pathlib.Path(sys.argv[2]).resolve();base.mkdir(parents=True,exist_ok=True)
checks=[]
def run(args,ok=True,contains=None):
 p=subprocess.run([binary,*args],capture_output=True,text=True,timeout=20)
 assert (p.returncode==0)==ok, (args,p.returncode,p.stderr)
 if contains: assert contains in p.stdout+p.stderr,(args,p.stdout,p.stderr)
 return p
before=subprocess.check_output(['ip','-j','route','show','table','all'])
with tempfile.TemporaryDirectory(prefix='cli-smoke-',dir=base) as tmp:
 d=pathlib.Path(tmp);source=d/'client.toml';report=d/'report.json';output=d/'tuned.toml'
 source.write_text("[keys]\nprivate_key='public-test-dummy'\nserver_pub_key='public-test-dummy'\n[main]\ntun_name='anet-cli-smoke'\n[[servers]]\ndsn='quic://127.0.0.1:9'\n")
 orig=hashlib.sha256(source.read_bytes()).hexdigest()
 common=['--cfg',str(source)]
 run(['--version'],contains='1.0.3');checks.append('product_version')
 p=run(common+['--diagnose','--diagnostics-json',str(report)])
 data=json.loads(p.stdout)
 assert data['profile_id']==orig and data['network_context'].startswith('linux-routes:')
 assert (report.stat().st_mode&0o777)==0o600
 checks.append('diagnostics_profile_network_binding_private_report')
 plan=json.loads(run(common+['--tuning-report',str(report)]).stdout)
 assert plan['max_connections']==1 and plan['min_connect_interval_ms']>=500
 assert 'dsn' not in plan['candidates'][0]
 checks.append('preview_limits_no_dsn_credentials')
 run(common+['--tuning-report',str(report),'--tuning-candidate','0','--tuning-output',str(output)])
 assert (output.stat().st_mode&0o777)==0o600
 assert 'max_connections = 1' in output.read_text()
 checks.append('export_separate_private_toml')
 run(common+['--tuning-report',str(report),'--tuning-candidate','0','--tuning-output',str(source)],False,contains='refusing_to_overwrite')
 checks.append('reject_source_overwrite')
 run(common+['--tuning-report',str(report),'--tuning-candidate','999','--tuning-output',str(output)],False)
 checks.append('reject_unknown_candidate')
 for field,value in [('created_at_ms',1),('network_context','linux-routes:wrong'),('profile_id','wrong'),('cancelled',True)]:
  changed=dict(data);changed[field]=value;invalid=d/'invalid.json';invalid.write_text(json.dumps(changed))
  run(common+['--tuning-report',str(invalid)],False)
 checks.append('reject_expired_network_profile_cancelled_reports')
 interfaces=json.loads(subprocess.check_output(['ip','-j','-d','address','show']))
 if any('UP' in a.get('flags',[]) and (a.get('ifname','').startswith(('tun','tap','wg','anet')) or a.get('linkinfo',{}).get('info_kind') in ('tun','wireguard')) for a in interfaces):
  run(common+['--tuning-report',str(report),'--tuning-candidate','0','--tuning-connect'],False,contains='active VPN/tunnel')
  checks.append('reject_connect_while_working_tunnel_exists')
 cache=d/'cache.json';cache.write_text(json.dumps({'schema_version':1,'report':data,'group':'','candidate':0,'verified_at_ms':1,'verification':{'authenticated':False,'data_verified':False}}))
 run(['--reset-tuning-cache',str(cache)])
 assert not cache.exists();checks.append('reset_cache_without_cfg_or_vpn')
 run(common+['--tuning-report',str(report),'--dpi-helper','/unused'],False,contains='Diagnostic options require')
 checks.append('reject_mixed_diagnostic_options')
 assert hashlib.sha256(source.read_bytes()).hexdigest()==orig
 checks.append('original_profile_unchanged')
after=subprocess.check_output(['ip','-j','route','show','table','all'])
assert before==after,'Route state changed during local smoke test'
checks.append('route_tables_unchanged')
print(json.dumps({'passed':len(checks),'checks':checks,'live_vpn_session_started':False},indent=2))
