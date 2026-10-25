#pragma once
#include <algorithm>
#include <cmath>
#include <deque>
#include <utility>
// Exact scalar formulas only. Packet transport, observation mapping, thresholds
// and recovery remain the declared common wrapper, not the published protocols.
namespace published {
inline double Gtms(unsigned s,unsigned f){return s+f?std::round(100.0*s*s/((s+f)*(s+1.0)))/100:.5;}
inline double EdtmCommunication(unsigned s,unsigned f){return (s+.5)/(s+f+1.0);}
inline double LtmhlPenalty(double prior,bool successful){return successful?prior:std::max(0.0,prior-.1);}
struct Window {
 std::deque<std::pair<unsigned,bool>> observations;
 std::pair<unsigned,unsigned> Counts(unsigned round,unsigned width){
  while(!observations.empty()&&round-observations.front().first>=width)observations.pop_front();
  unsigned success=0;for(auto [t,good]:observations)success+=good;
  return {success,unsigned(observations.size())-success};
 }
};
}
