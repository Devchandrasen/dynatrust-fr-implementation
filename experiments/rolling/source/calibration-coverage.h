#pragma once
#include "temporal-evidence.h"
#include <limits>
#include <map>
#include <deque>

namespace calibration {
struct Baseline {unsigned count=0;double sum=0,squares=0;
void Observe(double x){sum+=x;squares+=x*x;++count;}
double Mean()const{return count?sum/count:0;}
double SD()const{return count>1?std::sqrt(std::max(0.0,(squares-sum*sum/count)/(count-1))):1e9;}};
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
inline std::vector<unsigned> Greedy(const std::vector<std::vector<double>>& r,const std::vector<bool>& eligible,unsigned k,const std::vector<double>& bonus={}){
    std::vector<unsigned> chosen;std::vector<double> covered(r.size(),0);
    while(chosen.size()<k){int best=-1;double bestGain=-1;
        for(unsigned j=0;j<eligible.size();++j)if(eligible[j]&&std::find(chosen.begin(),chosen.end(),j)==chosen.end()){
            double gain=bonus.empty()?0:bonus[j];for(unsigned i=0;i<r.size();++i)gain+=std::max(0.0,r[i][j]-covered[i]);
            if(gain>bestGain){best=j;bestGain=gain;}
        }
        if(best<0)break;chosen.push_back(best);for(unsigned i=0;i<r.size();++i)covered[i]=std::max(covered[i],r[i][best]);
    }
    return chosen;
}
}

namespace sequential {
struct Cusum {
    double positive=0,negative=0;
    void Observe(double standardized,double k,double limit){
        // Bounded memory permits recovery; cap is declared, not a truth label.
        positive=std::min(2*limit,std::max(0.0,positive+standardized-k));
        negative=std::min(2*limit,std::max(0.0,negative-standardized-k));
    }
    bool Reject(double limit)const{return positive>limit||negative>limit;}
};
struct CommonEvent {
    unsigned last=0,streak=0;double pending=0;
    calibration::Reference Observe(std::vector<double> values,unsigned registered,
        unsigned round,double radius,double continuity){
        // Values must be deduplicated by authenticated source before this call.
        if(values.size()<3){streak=0;return {};}
        std::vector<std::pair<double,double>> v;for(double x:values)v.push_back({x,1});
        double center=temporal::WeightedMedian(v);unsigned support=0;
        for(double x:values)if(std::abs(x-center)<=radius)++support;
        const unsigned required=(2*registered+2)/3;
        if(support<required){streak=0;return {};}
        streak=(streak&&round==last+1&&std::abs(center-pending)<=continuity)?streak+1:1;
        pending=center;last=round;
        return streak>=2?calibration::Reference{true,center}:calibration::Reference{};
    }
    void Reset(){streak=0;}
};
}


namespace recovery {
struct RollingReference {
    struct Item {double value;unsigned round;};
    std::map<unsigned,Item> latest;
    unsigned last=0,streak=0;double pending=0;
    calibration::Reference Observe(const std::map<unsigned,double>& observations,
      unsigned registered,unsigned round,unsigned age,double radius,double continuity){
        for(auto [id,x]:observations)if(id<registered)latest[id]={x,round};
        for(auto it=latest.begin();it!=latest.end();)
            if(round-it->second.round>age)it=latest.erase(it);else ++it;
        std::vector<std::pair<double,double>> values;
        for(auto [id,item]:latest)values.push_back({item.value,1});
        std::sort(values.begin(),values.end());
        std::vector<std::pair<double,double>> cluster;unsigned matches=0;double center=0;
        auto close=[&](){
            if(cluster.size()>registered/2){
                double m=temporal::WeightedMedian(cluster);unsigned support=0;
                for(auto [x,weight]:cluster)if(std::abs(x-m)<=radius)++support;
                if(support>registered/2){center=m;++matches;}
            }cluster.clear();
        };
        for(unsigned i=0;i<values.size();++i){
            if(i&&values[i].first-values[i-1].first>2*radius)close();
            cluster.push_back(values[i]);
        }close();
        if(matches!=1){streak=0;return {};}
        streak=(streak&&round==last+1&&std::abs(center-pending)<=continuity)?streak+1:1;
        pending=center;last=round;
        return streak>=2?calibration::Reference{true,center}:calibration::Reference{};
    }
};
struct AlarmRelease {
    std::deque<std::pair<unsigned,double>> residuals;
    bool Observe(bool alarm,double z,unsigned round,unsigned required,double margin){
        if(!alarm){residuals.clear();return false;}
        residuals.push_back({round,z});
        while(residuals.size()>required)residuals.pop_front();
        if(residuals.size()<required||round-residuals.front().first>2*required)return false;
        double sum=0;for(auto [t,x]:residuals)sum+=x;
        if(std::abs(sum/required)>margin)return false;
        residuals.clear();return true;
    }
};
}

namespace recovery {
struct RecentBand {
 std::deque<std::pair<unsigned,double>> recent;
 bool Observe(double z,unsigned round,unsigned count,double bound){
  recent.push_back({round,z});while(recent.size()>count)recent.pop_front();
  if(recent.size()<count||round-recent.front().first>2*count)return false;
  double sum=0;for(auto [t,v]:recent)sum+=v;
  return std::abs(sum/count)<=bound;
 }
};
}
