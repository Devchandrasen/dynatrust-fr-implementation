#pragma once
#include <algorithm>
#include <cmath>
#include <utility>
#include <vector>

// Candidate detector: only authenticated received values, time and observed
// head-path weights enter this module. No source truth or attack labels.
namespace temporal {
inline double WeightedMedian(std::vector<std::pair<double,double>> values){
    std::sort(values.begin(),values.end());double total=0,cumulative=0;
    for(auto [x,w]:values)total+=w;
    for(unsigned i=0;i<values.size();++i){
        cumulative+=values[i].second;
        if(std::abs(cumulative-total/2)<1e-10 && i+1<values.size())return (values[i].first+values[i+1].first)/2;
        if(cumulative>total/2)return values[i].first;
    }
    return values.empty()?0:values.back().first;
}
inline bool Ambiguous(std::vector<std::pair<double,double>> values,double tolerance){
    if(values.size()<3)return false;
    std::sort(values.begin(),values.end());double total=0,left=0;
    for(auto [x,w]:values)total+=w;
    for(unsigned i=0;i+1<values.size();++i){
        left+=values[i].second;
        if(values[i+1].first-values[i].first>2*tolerance && left>=.45*total && total-left>=.45*total)return true;
    }
    return false;
}
struct History {
    unsigned count=0,last=0;
    double weight=0,squaredWeight=0,sum=0,squares=0;
    void Observe(double residual,unsigned round,double gain){
        const double decay=1-gain;
        weight=decay*weight+gain;
        squaredWeight=decay*decay*squaredWeight+gain*gain;
        sum=decay*sum+gain*residual;
        squares=decay*squares+gain*residual*residual;
        ++count;last=round;
    }
    double Mean()const{return weight?sum/weight:0;}
    double EffectiveN()const{return squaredWeight?weight*weight/squaredWeight:0;}
    double SE()const{
        const double n=EffectiveN(),v=weight?std::max(0.0,squares/weight-Mean()*Mean()):0;
        return n>1?std::sqrt(std::max(.01,v)*n/(n-1)/n):1e9;
    }
};
struct Peer{double mean,se,weight;};
struct Contrast{bool available=false;double center=0,se=0;};
inline Contrast PeerContrast(const std::vector<Peer>& peers){
    if(peers.size()<3)return {};
    std::vector<std::pair<double,double>> centers,errors;
    for(const auto& p:peers){centers.push_back({p.mean,p.weight});errors.push_back({p.se,p.weight});}
    return {true,WeightedMedian(centers),WeightedMedian(errors)};
}
inline bool Reject(const History& history,const Contrast& peers,double margin,double z){
    return peers.available && std::abs(history.Mean()-peers.center)>margin+z*std::hypot(history.SE(),peers.se);
}
}
