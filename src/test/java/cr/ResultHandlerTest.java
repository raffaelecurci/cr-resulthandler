package cr;

import java.util.regex.Pattern;

import org.junit.Test;

import cr.service.VeracodeAdapter;

//@RunWith(SpringRunner.class)
//@SpringBootTest
public class ResultHandlerTest {
//	@Test
	public void login() {

		
//		FlawList fl=wrh.getDetailedResult(new Long("3150830"));
//		System.out.println(fl.toString());
		
//		List<VeracodeInfo>vil=wrh.getVeracodeApplicationsBuilds();
//		Optional<VeracodeInfo> qwe = vil.stream().filter(f->f.getCommitHash().equals("fc2f614ac430c3ee9425969914adda2b73fae20e")).findAny();
//		if(qwe.isPresent()) {
//			VeracodeInfo vi=qwe.get();
//			FlawList fl=wrh.getDetailedResult(vi.getBuild_id());
//			System.out.println(fl);
//			System.out.println(vi.getBuild_id());
//		}
	}
	@Test
	public void veracodeAdapter() {
		VeracodeAdapter va=new VeracodeAdapter("veracodeuser", "veracodepassword");
		System.out.println(va.getAppList()+"\n\n\n");
//		System.out.println(va.getBuildList(439820L));//439820
		
	}
	
//	@Test
	public void match() {
		if(Pattern.matches("[a-zA-Z]+-+[0-9]+-\\w{40}", "jenkinsJava-45-fc2f614ac430c3ee9425969914adda2b73fae20e")) {
			System.out.println("ok");
		}
	}
}
