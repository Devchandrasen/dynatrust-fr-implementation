#pragma once
#include "temporal-evidence.h"
#include <limits>

namespace calibration {
struct Baseline {unsigned count=0;double sum=0;void Observe(double x){sum+=x;++count;}double Mean()const{return count?sum/count:0;}};
struct Reference {bool available=false;double value=0;};
inline Reference Anchor(std::vector<std::pair<double,double>> values,bool initialized,double previous,double step,double tolerance,unsigned minimum){
    if(!initialized||values.size()<minimum)return {};
    std::sort(values.begin(),values.end());
    std::vector<std::pair<double,double>> cluster;Reference candidate;unsigned matches=0;
    auto close=[&](){if(cluster.size()>=minimum){double m=temporal::WeightedMedian(cluster);if(std::abs(m-previous)<=step){candidate={true,m};++matches;}}cluster.clear();};
    for(unsigned i=0;i<values.size();++i){if(i&&values[i].first-values[i-1].first>2*tolerance)close();cluster.push_back(values[i]);}close();
    return matches==1?candidate:Reference{};
}
}
namespace coverage {
inline double Utility(const std::vector<std::vector<double>>& r,const std::vector<unsigned>& heads){
    double f=0;for(const auto& row:r){double b=0;for(auto h:heads)b=std::max(b,row[h]);f+=b;}return f;
}
inline std::vector<unsigned> Greedy(const std::vector<std::vector<double>>& r,const std::vector<bool>& eligible,unsigned k){
    std::vector<unsigned> chosen;std::vector<double> covered(r.size(),0);
    while(chosen.size()<k){int best=-1;double bestGain=-1;
        for(unsigned j=0;j<eligible.size();++j)if(eligible[j]&&std::find(chosen.begin(),chosen.end(),j)==chosen.end()){
            double gain=0;for(unsigned i=0;i<r.size();++i)gain+=std::max(0.0,r[i][j]-covered[i]);
            if(gain>bestGain){best=j;bestGain=gain;}
        }
        if(best<0)break;chosen.push_back(best);for(unsigned i=0;i<r.size();++i)covered[i]=std::max(covered[i],r[i][best]);
    }
    return chosen;
}
}
