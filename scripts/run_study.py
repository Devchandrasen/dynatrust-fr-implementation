"""Build a source snapshot and replay selected recorded cases into a new folder."""
from pathlib import Path
import argparse,csv,gzip,hashlib,io,json,os,shutil,subprocess,time
from study_common import ROOT,catalog,digest,load,study

MODULES=['core','network','internet','internet-apps','mobility','lr-wpan','sixlowpan',
         'spectrum','propagation','antenna','traffic-control','bridge','stats']

def build(name,folder,manifest,runtime,cxx):
    version=(runtime/'VERSION').read_text().strip()
    if version!='3.47':raise ValueError(f'Expected ns-3.47; found {version}')
    for rel,expected in manifest['source_sha256'].items():
        if digest((folder/rel).read_bytes())!=expected:raise ValueError(f'Source checksum mismatch: {rel}')
    libdir=runtime/'build/lib'
    libraries=sorted(libdir.glob('libns3.47-core-*.so'))
    if not libraries:raise ValueError(f'No built ns-3.47 shared libraries in {libdir}')
    profile=libraries[0].name.removeprefix('libns3.47-core-').removesuffix('.so')
    target=ROOT/'build/bin'/name;target.parent.mkdir(parents=True,exist_ok=True)
    command=[cxx,'-std=c++20','-O3','-DNDEBUG','-I'+str(runtime/'build/include'),
             str(folder/manifest['program']),'-o',str(target),'-L'+str(libdir),
             '-Wl,-rpath,'+str(libdir),*[f'-lns3.47-{m}-{profile}' for m in MODULES],'-ldl']
    subprocess.run(command,check=True)
    return target,command

def compare(expected,actual):
    with gzip.open(expected,'rt',newline='') as stream:a=csv.DictReader(stream);header=a.fieldnames;first=list(a)
    with actual.open(newline='') as stream:b=csv.DictReader(stream);other=b.fieldnames;second=list(b)
    if header!=other:return {'columns':{'expected':header,'actual':other}}
    if len(first)!=len(second):return {'rows':{'expected':len(first),'actual':len(second)}}
    diffs=[]
    for i,(a,b) in enumerate(zip(first,second)):
        for key in header:
            if a[key]!=b[key]:
                diffs.append({'round':i,'field':key,'expected':a[key],'actual':b[key]})
                if len(diffs)>=20:return {'first_differences':diffs}
    return {'first_differences':diffs} if diffs else None

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list',action='store_true');parser.add_argument('--study')
    for key in ['phase','scenario','variant']:parser.add_argument('--'+key)
    parser.add_argument('--seed',type=int);parser.add_argument('--limit',type=int)
    parser.add_argument('--output',type=Path);parser.add_argument('--ns3-root',type=Path,default=os.environ.get('NS3_ROOT'))
    parser.add_argument('--cxx',default='g++');args=parser.parse_args()
    if args.list:
        for entry in catalog()['studies']:print(f"{entry['id']:14} {entry['missions']:5} missions  {entry['rounds']:7} rounds")
        return
    if not args.study or not args.output or not args.ns3_root:parser.error('--study, --output and --ns3-root are required')
    if args.limit is not None and args.limit<1:parser.error('--limit must be positive')
    folder,manifest=study(args.study)
    cases=[c for c in manifest['cases'] if all(getattr(args,k) is None or c[k]==getattr(args,k) for k in ['phase','scenario','variant','seed'])]
    if args.limit:cases=cases[:args.limit]
    if not cases:parser.error('No recorded cases match the selected filters')
    output=args.output.resolve();protected=(ROOT/'experiments').resolve()
    if output==protected or protected in output.parents:parser.error('Choose an output outside experiments/')
    if output.exists():parser.error('Choose a new output directory')
    if not shutil.which(args.cxx):parser.error(f'Compiler not found: {args.cxx}')
    runtime=args.ns3_root.resolve();output.mkdir(parents=True)
    exe,build_command=build(args.study,folder,manifest,runtime,args.cxx)
    results=[]
    for item in cases:
        record=load(folder/item['record']);work=output/item['phase']/item['scenario'];work.mkdir(parents=True,exist_ok=True)
        arguments=list(record['arguments'])
        if 'calibration_fixture' in record:
            source=folder/record['calibration_fixture'];dest=work/'calibration'/source.name;dest.parent.mkdir(exist_ok=True)
            if dest.exists():assert dest.read_bytes()==source.read_bytes()
            else:shutil.copy2(source,dest)
            arguments.append('--calibrationFile=calibration/'+source.name)
        csvfile=work/(item['id']+'.csv')
        command=[str(exe),*arguments,'--output='+csvfile.name]
        started=time.monotonic();subprocess.run(command,cwd=work,check=True,capture_output=True,text=True)
        difference=compare(folder/item['raw'],csvfile)
        result={'case':item['id'],'phase':item['phase'],'arguments':arguments,'match':difference is None,
                'csv':str(csvfile.relative_to(output)),'sha256':digest(csvfile.read_bytes()),'seconds':time.monotonic()-started}
        if difference:result['difference']=difference
        results.append(result);print(('MATCH ' if result['match'] else 'DIFFER ')+item['id'],flush=True)
    report={'study':args.study,'runtime':str(runtime),'build_command':build_command,'cases':results,'all_match':all(x['match'] for x in results)}
    (output/'replay.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    if not report['all_match']:raise SystemExit('Replay differences recorded in '+str(output/'replay.json'))
    print(f'Replayed {len(results)} matching cases. Report: {output / "replay.json"}',flush=True)
if __name__=='__main__':main()
