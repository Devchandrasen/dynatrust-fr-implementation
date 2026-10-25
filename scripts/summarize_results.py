"""Export grouped means and sample standard deviations across recorded seeds."""
from pathlib import Path
from collections import defaultdict
import argparse,csv,statistics
from study_common import ROOT,load,study

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--study',required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    protected=(ROOT/'experiments').resolve();target=args.output.resolve()
    if target==protected or protected in target.parents:parser.error('Choose an output outside experiments/')
    if target.exists():parser.error('Choose a new output file')
    folder,manifest=study(args.study);groups=defaultdict(list)
    for item in manifest['cases']:groups[(item['phase'],item['scenario'],item['variant'])].append(load(folder/item['record'])['overall'])
    rows=[];fields=set()
    for (phase,scenario,variant),items in sorted(groups.items()):
        row={'study':args.study,'phase':phase,'scenario':scenario,'variant':variant,'seeds':len(items)}
        for key in sorted(set.intersection(*(set(x) for x in items))):
            values=[x[key] for x in items if isinstance(x[key],(int,float))]
            if not values:continue
            row[key+'_mean']=statistics.mean(values);row[key+'_sd']=statistics.stdev(values) if len(values)>1 else 0
        fields.update(row);rows.append(row)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    initial=['study','phase','scenario','variant','seeds']
    with args.output.open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=initial+sorted(fields-set(initial)));writer.writeheader();writer.writerows(rows)
    print(f'Exported {len(rows)} groups to {args.output}')
if __name__=='__main__':main()
