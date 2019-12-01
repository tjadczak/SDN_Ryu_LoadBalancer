  sudo mn --custom topology.py --topo mytopo --mac --controller remote --switch ovsk --link=tc
  sudo ryu-manager Traffic_Monitor.py 
