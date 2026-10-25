"""Compile and execute the component checks for each source snapshot."""
import argparse,csv,shutil,subprocess
from study_common import ROOT,catalog,study

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--study');parser.add_argument('--cxx',default='g++');args=parser.parse_args()
    if not shutil.which(args.cxx):parser.error(f'Compiler not found: {args.cxx}')
    names=[args.study] if args.study else [x['id'] for x in catalog()['studies']]
    suites=0
    for name in names:
        folder,_=study(name);out=ROOT/'build/tests'/name;out.mkdir(parents=True,exist_ok=True)
        for source in sorted((folder/'tests').glob('*.cc')):
            exe=out/source.stem
            command=[args.cxx,'-std=c++17','-O2',str(source),'-o',str(exe),'-ldl']
            result=subprocess.run(command,capture_output=True,text=True)
            if result.returncode:raise RuntimeError(result.stdout+result.stderr)
            command=[str(exe)]
            if source.stem=='fusion_stress_final':command.append(str(out/'fusion_trials.csv'))
            result=subprocess.run(command,capture_output=True,text=True)
            if result.returncode:raise RuntimeError(f'{name}/{source.name}:\n'+result.stdout+result.stderr)
            if source.stem=='fusion_stress_final':
                with (out/'fusion_trials.csv').open() as stream:assert sum(1 for _ in csv.DictReader(stream))==7200
            print(f'PASS {name}/{source.stem}: {result.stdout.strip()}',flush=True)
            suites+=1
    print(f'Passed {suites} C++ suites.',flush=True)
if __name__=='__main__':main()
