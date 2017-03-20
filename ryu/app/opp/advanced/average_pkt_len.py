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
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {eth_dst}  """
		req = oppparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=oppproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		###########################################################################################

		""" Set HF[1]=PKT_LEN [byte]"""
		req = oppparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=1,
				field=oppproto.OXM_EXP_PKT_LEN
			)
		datapath.send_msg(req)

		""" Update function: avg( [count] , [value_to_be_averaged] , [avg_value]) = (IO1 , IN1 , IO2) has 3 inputs and 2 outputs
        	OUT1 = FDV[0] = count
       		OUT2 = FDV[1] = avg(IN1)*1000
       	"""
		match = ofparser.OFPMatch()
		actions = [ofparser.OFPActionOutput(ofproto.OFPP_FLOOD),
			oppparser.OFPExpActionSetDataVariable(table_id=0, opcode=oppproto.OPCODE_AVG, output_fd_id=0, operand_1_hf_id=1, operand_2_fd_id=1)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		""" $ sudo watch --color -n1 dpctl tcp:127.0.0.1:6634 stats-state -c
			mininet> h1 ping h2 -s 100 -c 10
			mininet> h1 ping h2 -s 200 -c 10

			PKT_LEN = 42+payload => avg(PKT_LEN)=(10*142+10*242)/20=191.997~192
		"""
