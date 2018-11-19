package cr.listeners;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import cr.ResultHandlerApplication;
import cr.generated.interf.Listener;
import cr.generated.ops.MessageListener;
import cr.generated.ops.service.RPCClient;
import cr.interf.EncryptedMessage;
import cr.service.VeracodeAdapter;
import cr.shared.FlawList;
import cr.shared.JenkinsBuildInfo;
import cr.shared.VeracodeInfo;

@RefreshScope
@Configuration
public class ApplicationListener {
	@Autowired
	private RPCClient client;
	private static String encryption=ResultHandlerApplication.class.getAnnotation(cr.annotation.QueueDefinition.class).encryption();
	private static Logger log = LoggerFactory.getLogger(ApplicationListener.class);
	
	@Value("${veracode.user}")
	private String veracodeUser;
	@Value("${veracode.passwd}")
	private String veracodePasswd;
	
	@Bean
	public MessageListener messageListener() {
		return new MessageListener();
	} 
	
	@Bean
	public Listener listener() {
		return new Listener() {
			@Override
			public void processRes(EncryptedMessage message) {
				log.info("Received: "+message);
				action(message);
			}
		};
	}
	public void action(EncryptedMessage message) {
		if (message.getPayloadType().equals("cr.shared.JenkinsBuildInfo"))
			retrieveScan(message);
	}
	private void retrieveScan(EncryptedMessage message) {
		JenkinsBuildInfo jbi=message.decodeBase64ToObject();
		System.out.println(veracodeUser+" ");
		VeracodeAdapter wrh=new VeracodeAdapter(veracodeUser, veracodePasswd);
		
		List<VeracodeInfo>via=wrh.getAppList();
		
		VeracodeInfo vi[]=new VeracodeInfo[1];
		
		System.out.println("Requesting flaws for "+jbi.getVeracodeScan());
		
		via.stream().forEach(v->{
			Optional<VeracodeInfo> tmp = wrh.getBuildList(v.getApp_id()).stream().filter(b->b.getCommitHash()!=null).filter(f->f.getVersion().equals(jbi.getVeracodeScan())).findAny();
			if(tmp.isPresent()) {
				vi[0]=tmp.get();
				System.out.println("Found build "+vi[0].getBuild_id()+" for version "+vi[0].getVersion());
				return;
			}
		});
		
		if(vi[0]!=null) {
			FlawList fl=wrh.getDetailedResult(vi[0].getBuild_id());
			if(fl.getFlaws().size()>0) {
				client.sendAndReceiveDb(fl.toEncryptedMessage(encryption).encodeBase64());
				System.out.println(vi[0].getBuild_id());
			}
		}
		
	}
}

