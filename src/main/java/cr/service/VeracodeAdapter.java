package cr.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.net.ssl.HttpsURLConnection;
import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.fasterxml.jackson.databind.ObjectMapper;

import cr.shared.Flaw;
import cr.shared.FlawList;
import cr.shared.VeracodeInfo;

public class VeracodeAdapter {
	static private Logger log = LoggerFactory.getLogger(VeracodeAdapter.class);
	private static String regexToValidateVersion = "[a-zA-Z]+[-][#][0-9]+[-]\\w{40}";
	private String passwd;
	private String username;
	private ObjectMapper om;

	public VeracodeAdapter(String username, String passwd) {
		this.passwd = passwd;
		this.username = username;
		om = new ObjectMapper();
	}

	public List<VeracodeInfo> getAppList() {
		String destination = "https://analysiscenter.veracode.com/api/5.0/getapplist.do";
		String method = "GET";
		String response = readResponse(connectTo(destination, method, null));
		List<VeracodeInfo> vi = new LinkedList<VeracodeInfo>();
		try {
			if (response != null) {
				NodeList app = getNodeElement(response, "app");
				for (int i = 0; i < app.getLength(); i++) {
					JSONObject json = new JSONObject();
					json.put("app_id", ((Element) app.item(i)).getAttribute("app_id"));
					json.put("app_name", ((Element) app.item(i)).getAttribute("app_name"));
					json.put("version", "0-0-0");
					vi.add(om.readValue(json.toString(), VeracodeInfo.class));
				}
			}
		} catch (SAXException | IOException | ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return vi;
	}

	public List<VeracodeInfo> getBuildList(Long app_id) {
		String destination = "https://analysiscenter.veracode.com/api/5.0/getbuildlist.do";
		String method = "GET";
		Map<String, String> params = new HashMap<String, String>();
		params.put("app_id", app_id.toString());
		String response = readResponse(connectTo(destination, method, params));
		List<VeracodeInfo> vi = new LinkedList<VeracodeInfo>();
		if (response != null) {
			try {
				NodeList build = getNodeElement(response, "build");
				for (int i = 0; i < build.getLength(); i++) {
					JSONObject json = new JSONObject();
					json.put("app_id", app_id);
					json.put("build_id", ((Element) build.item(i)).getAttribute("build_id"));
					json.put("version", ((Element) build.item(i)).getAttribute("version"));
					if (Pattern.matches(regexToValidateVersion, json.getString("version")))
						vi.add(om.readValue(json.toString(), VeracodeInfo.class));
				}
			} catch (IOException | SAXException | ParserConfigurationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return vi;
	}

	public FlawList getDetailedResult(Long buildId) {
		ObjectMapper om = new ObjectMapper();
		FlawList fl = new FlawList();
		List<Flaw> flowList = new LinkedList<Flaw>();
		JSONObject json = null;
		try {
			String destination = "https://analysiscenter.veracode.com/api/5.0/detailedreport.do";
			String method = "GET";
			Map<String, String> params = new HashMap<String, String>();
			params.put("build_id", buildId.toString());
			String xmlReport = readResponse(connectTo(destination, method, params));
			NodeList detailedreport = getNodeElement(xmlReport, "detailedreport");//detailedreport
			NodeList static_analysis = getNodeElement(xmlReport, "static-analysis");
			NodeList severity = getNodeElement(xmlReport, "severity");
			NodeList module = getNodeElement(xmlReport, "module");
			Long app_id =new Long(((Element) detailedreport.item(0)).getAttribute("app_id"));
			Long build_id=new Long(((Element) detailedreport.item(0)).getAttribute("build_id"));
			Long analysis_size_bytes = new Long(((Element) static_analysis.item(0)).getAttribute("analysis_size_bytes"));
			String rating = "" + ((Element) static_analysis.item(0)).getAttribute("rating");
			Integer score = new Integer(((Element) static_analysis.item(0)).getAttribute("score"));
			String version = "" + ((Element) static_analysis.item(0)).getAttribute("version");
			Long loc = new Long(((Element) module.item(0)).getAttribute("loc"));
			Long sev = null;
			for (int i = 0; i < severity.getLength(); i++) {// loop on severities
				sev = new Long(((Element) severity.item(i)).getAttribute("level"));
				String sv = nodeToString(severity.item(i));
				NodeList categories = getNodeElement(sv, "category");
				for (int j = 0; j < categories.getLength(); j++) {
					Integer categoryid = new Integer(((Element) categories.item(j)).getAttribute("categoryid"));
					String categoryname = ((Element) categories.item(j)).getAttribute("categoryname");

					String dsc = nodeToString(categories.item(j));
					NodeList dscn = getNodeElement(dsc, "desc");
					String para = nodeToString(dscn.item(0));
					NodeList paral = getNodeElement(para, "para");
					String desc0 = "";
					for (int k = 0; k < paral.getLength(); k++) {
						if (k < paral.getLength() - 1) {
							desc0 += ((Element) paral.item(k)).getAttribute("text") + "\n";
						} else {
							desc0 += ((Element) paral.item(k)).getAttribute("text");
						}
					}

					dscn = getNodeElement(dsc, "recommendations");
					para = nodeToString(dscn.item(0));
					paral = getNodeElement(para, "para");
					String desc2 = "";
					for (int k = 0; k < paral.getLength(); k++) {
						if (k < paral.getLength() - 1) {
							desc2 += ((Element) paral.item(k)).getAttribute("text") + "\n";
						} else {
							desc2 += ((Element) paral.item(k)).getAttribute("text");
						}
					}
					NodeList cwes = getNodeElement(dsc, "cwe");
					for (int k = 0; k < cwes.getLength(); k++) {
						Long cweid = new Long(((Element) cwes.item(k)).getAttribute("cweid"));
						String cwename = ((Element) cwes.item(k)).getAttribute("cwename");
						Boolean cwepcirelated = new Boolean(((Element) cwes.item(k)).getAttribute("cwepcirelated"));

						paral = getNodeElement(nodeToString(cwes.item(k)), "text");
						String desc = "";
						for (int y = 0; y < paral.getLength(); y++) {
							if (y < paral.getLength() - 1) {
								desc += ((Element) paral.item(y)).getAttribute("text") + "\n";
							} else {
								desc += ((Element) paral.item(y)).getAttribute("text");
							}
						}

						paral = getNodeElement(nodeToString(cwes.item(k)), "flaw");
						for (int y = 0; y < paral.getLength(); y++) {
							json = new JSONObject();
							Boolean affects_policy_compliance = new Boolean(
									((Element) paral.item(y)).getAttribute("affects_policy_compliance"));
							String cia_impact = ((Element) paral.item(y)).getAttribute("cia_impact");// cia_impact
							Integer count = new Integer(((Element) paral.item(y)).getAttribute("count"));// count
							String flaw_description = ((Element) paral.item(y)).getAttribute("description");// description
							Integer exploitLevel = new Integer(((Element) paral.item(y)).getAttribute("exploitLevel"));// exploitLevel
							String functionprototype = ((Element) paral.item(y)).getAttribute("functionprototype");// functionprototype
							Integer functionrelativelocation = new Integer(
									((Element) paral.item(y)).getAttribute("functionrelativelocation"));// functionrelativelocation
							Integer issueid = new Integer(((Element) paral.item(y)).getAttribute("issueid"));// issueid
							Integer line = new Integer(((Element) paral.item(y)).getAttribute("line"));// line
							Boolean pcirelated = new Boolean(((Element) paral.item(y)).getAttribute("pcirelated"));// pcirelated
							String scope = ((Element) paral.item(y)).getAttribute("scope");// scope
							String sourcefile = ((Element) paral.item(y)).getAttribute("sourcefile");// sourcefile
							String sourcefilepath = ((Element) paral.item(y)).getAttribute("sourcefilepath");// sourcefilepath
							String type = ((Element) paral.item(y)).getAttribute("type");// type
							
							json.put("app_id", app_id);
							json.put("build_id", build_id);
							
							json.put("affects_policy_compliance", affects_policy_compliance);
							json.put("cia_impact", cia_impact);
							json.put("count", count);
							json.put("flaw_description", flaw_description);
							json.put("exploitLevel", exploitLevel);
							json.put("functionprototype", functionprototype);
							json.put("functionrelativelocation", functionrelativelocation);
							json.put("issueid", issueid);
							json.put("line", line);
							json.put("pcirelated", pcirelated);
							json.put("scope", scope);
							json.put("sourcefile", sourcefile);
							json.put("sourcefilepath", sourcefilepath);
							json.put("type", type);

							json.put("cweid", cweid);
							json.put("cwename", cwename);
							json.put("cwepcirelated", cwepcirelated);

							json.put("categoryname", categoryname);
							json.put("categoryid", categoryid);

							json.put("recommendation_description", desc2);
							json.put("cwe_description", desc);
							json.put("category_description", desc0);

							json.put("analysis_size_bytes", analysis_size_bytes);
							json.put("rating", rating);
							json.put("score", score);
							json.put("version", version);
							json.put("loc", loc);
							json.put("severity", sev);
							String flaw = json.toString();
							flowList.add(om.readValue(flaw, Flaw.class));
						}
					}
				}
				fl.setFlaws(flowList);
			}

		} catch (SAXException | TransformerException | ParserConfigurationException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return fl;
	}

	private String readResponse(HttpsURLConnection connection) {
		if (connection != null) {
			try {
				InputStream is = connection.getInputStream();
				BufferedReader br = new BufferedReader(new InputStreamReader(is));
				StringBuilder sb = new StringBuilder();
				br.lines().forEach(l -> sb.append(l + "\n"));
				if (!sb.toString().contains("<error>"))
					return sb.toString();
				else
					return null;
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return null;
	}

	private HttpsURLConnection connectTo(String destination, String method, Map<String, String> params) {
		HttpsURLConnection connection = prepairHttpRequest(destination, method, params);
		try {
			connection.connect();
			log.info("Connection to " + destination + " resulted " + connection.getResponseCode() + " "
					+ connection.getResponseMessage());
			return connection;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

	}

	private HttpsURLConnection prepairHttpRequest(String URL, String method, final Map<String, String> params) {
		String getParam = "?";
		if (params != null) {
			if (method.equals("POST")) {
				// TBD
			} else if (method.equals("GET")) {
				getParam += String.join("&",
						params.keySet().stream().map(k -> k + "=" + params.get(k)).collect(Collectors.toList()));
			}
		}
		HttpsURLConnection connection = null;
		try {
			URL url = new URL(URL + (getParam.equals("?") ? "" : getParam));
			String authStr = username + ":" + passwd;
			String encoding = DatatypeConverter.printBase64Binary(authStr.getBytes());
			connection = (HttpsURLConnection) url.openConnection();
			connection.setRequestMethod(method);
			connection.setDoOutput(true);
			connection.setDoInput(true);
			connection.setRequestProperty("Authorization", " Basic " + encoding);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return connection;
	}

	private static NodeList getNodeElement(String xmlRecords, String tag)
			throws SAXException, IOException, ParserConfigurationException {
		DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
		InputSource is = new InputSource();
		is.setCharacterStream(new StringReader(xmlRecords));
		Document doc = db.parse(is);
		return doc.getElementsByTagName(tag);
	}

	private static String nodeToString(Node node) throws TransformerException {
		StringWriter buf = new StringWriter();
		Transformer xform = TransformerFactory.newInstance().newTransformer();
		xform.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		xform.transform(new DOMSource(node), new StreamResult(buf));
		return (buf.toString());
	}
}
