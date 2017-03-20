import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.opp_v1_0 as oppproto
import ryu.ofproto.opp_v1_0_parser as oppparser

LOG = logging.getLogger('app.opp.evolution')


class OppEvolution(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(OppEvolution, self).__init__(*args, **kwargs)

	def add_flow(self, datapath, table_id, priority, match, actions):
		if len(actions) > 0:
			inst = [ofparser.OFPInstructionActions(
					ofproto.OFPIT_APPLY_ACTIONS, actions)]
		else:
			inst = []
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
								priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, event):

		""" switch sent his features, check if Opp supported """
		msg = event.msg
		datapath = msg.datapath

		LOG.info("Configuring switch %d..." % datapath.id)

		""" Set table 0 as stateful """
		req = oppparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
				stateful=1)
		datapath.send_msg(req)

		""" Set lookup extractor = {eth_dst} """
		req = oppparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=oppproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC,ofproto.OXM_OF_ETH_DST],
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {eth_dst}  """
		req = oppparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=oppproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC,ofproto.OXM_OF_ETH_DST],
				table_id=0)
		datapath.send_msg(req)

		###########################################################################################

		""" State transition """
		match = ofparser.OFPMatch(in_port=3)
		actions = [oppparser.OFPExpActionSetState(table_id=0, state=1),
			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		""" State transition for the reverse flow """
		match = ofparser.OFPMatch(in_port=4)
		actions = [oppparser.OFPExpActionSetState(table_id=0, state=2, fields=[ofproto.OXM_OF_ETH_DST,ofproto.OXM_OF_ETH_SRC]),
			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		"""
		mininet> h3 ping h4 -c1

		$ sudo dpctl tcp:127.0.0.1:6634 stats-state table=0 eth_src=00:00:00:00:00:03 eth_dst=00:00:00:00:00:04 -c
		state = 2
		"""
		