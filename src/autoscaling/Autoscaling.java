package autoscaling;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.autoscaling.AmazonAutoScalingClient;
import com.amazonaws.services.autoscaling.model.CreateAutoScalingGroupRequest;
import com.amazonaws.services.autoscaling.model.CreateLaunchConfigurationRequest;
import com.amazonaws.services.autoscaling.model.DeleteAutoScalingGroupRequest;
import com.amazonaws.services.autoscaling.model.DeleteLaunchConfigurationRequest;
import com.amazonaws.services.autoscaling.model.DeletePolicyRequest;
import com.amazonaws.services.autoscaling.model.DescribeAutoScalingGroupsRequest;
import com.amazonaws.services.autoscaling.model.DescribeAutoScalingGroupsResult;
import com.amazonaws.services.autoscaling.model.DescribeLaunchConfigurationsRequest;
import com.amazonaws.services.autoscaling.model.DescribeLaunchConfigurationsResult;
import com.amazonaws.services.autoscaling.model.EnableMetricsCollectionRequest;
import com.amazonaws.services.autoscaling.model.InstanceMonitoring;
import com.amazonaws.services.autoscaling.model.PutScalingPolicyRequest;
import com.amazonaws.services.autoscaling.model.PutScalingPolicyResult;
import com.amazonaws.services.autoscaling.model.UpdateAutoScalingGroupRequest;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClient;
import com.amazonaws.services.cloudwatch.model.DeleteAlarmsRequest;
import com.amazonaws.services.cloudwatch.model.DescribeAlarmsRequest;
import com.amazonaws.services.cloudwatch.model.DescribeAlarmsResult;
import com.amazonaws.services.cloudwatch.model.Dimension;
import com.amazonaws.services.cloudwatch.model.PutMetricAlarmRequest;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressRequest;
import com.amazonaws.services.ec2.model.CreateSecurityGroupRequest;
import com.amazonaws.services.ec2.model.CreateSecurityGroupResult;
import com.amazonaws.services.ec2.model.CreateTagsRequest;
import com.amazonaws.services.ec2.model.DeleteSecurityGroupRequest;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.IpPermission;
import com.amazonaws.services.ec2.model.Reservation;
import com.amazonaws.services.ec2.model.RunInstancesRequest;
import com.amazonaws.services.ec2.model.RunInstancesResult;
import com.amazonaws.services.ec2.model.Tag;
import com.amazonaws.services.elasticloadbalancing.AmazonElasticLoadBalancingClient;
import com.amazonaws.services.elasticloadbalancing.model.AddTagsRequest;
import com.amazonaws.services.elasticloadbalancing.model.ConfigureHealthCheckRequest;
import com.amazonaws.services.elasticloadbalancing.model.ConfigureHealthCheckResult;
import com.amazonaws.services.elasticloadbalancing.model.ConnectionDraining;
import com.amazonaws.services.elasticloadbalancing.model.CreateLoadBalancerRequest;
import com.amazonaws.services.elasticloadbalancing.model.CreateLoadBalancerResult;
import com.amazonaws.services.elasticloadbalancing.model.DeleteLoadBalancerRequest;
import com.amazonaws.services.elasticloadbalancing.model.HealthCheck;
import com.amazonaws.services.elasticloadbalancing.model.Listener;
import com.amazonaws.services.elasticloadbalancing.model.LoadBalancerAttributes;
import com.amazonaws.services.elasticloadbalancing.model.ModifyLoadBalancerAttributesRequest;
import com.amazonaws.services.elasticloadbalancing.model.ModifyLoadBalancerAttributesResult;
import com.amazonaws.services.elasticloadbalancing.model.RegisterInstancesWithLoadBalancerRequest;
import com.amazonaws.services.elasticloadbalancing.model.RegisterInstancesWithLoadBalancerResult;

public class Autoscaling {
	static AmazonAutoScalingClient autoscalingGroup;
	static AmazonCloudWatchClient cloudwatch;
	static AmazonElasticLoadBalancingClient elb;
	static AmazonEC2Client amazonEC2Client;

	public static String CreateSecurity(AmazonEC2Client amazonEC2Client, String securitygroup) {
		// Create a Security Group to allow all traffic
		CreateSecurityGroupRequest csgr = new CreateSecurityGroupRequest();
		csgr.withGroupName(securitygroup).withDescription("My security group");
		CreateSecurityGroupResult createSecurityGroupResult = amazonEC2Client.createSecurityGroup(csgr);
		IpPermission ipPermission = new IpPermission();
		ipPermission.withIpRanges("0.0.0.0/0").withIpProtocol("-1").withFromPort(0).withToPort(65535);
		AuthorizeSecurityGroupIngressRequest authorizeSecurityGroupIngressRequest = new AuthorizeSecurityGroupIngressRequest();
		authorizeSecurityGroupIngressRequest.withGroupName(securitygroup).withIpPermissions(ipPermission);
		amazonEC2Client.authorizeSecurityGroupIngress(authorizeSecurityGroupIngressRequest);
		String securitygroupid = createSecurityGroupResult.getGroupId();
		System.out.println("1. Created the security group successfully: " + securitygroupid);
		return securitygroupid;
	}

	public static Instance CreateInstance(AmazonEC2Client amazonEC2Client, String ami, String type,
			String securitygroup) {
		// Create Instance Request
		RunInstancesRequest runInstancesRequest = new RunInstancesRequest();
		// Configure Instance Request
		runInstancesRequest.withImageId(ami).withInstanceType(type).withMinCount(1).withMaxCount(1)
				.withKeyName("15619key").withSecurityGroups(securitygroup).withMonitoring(true);

		// Launch Instance
		RunInstancesResult runInstancesResult = amazonEC2Client.runInstances(runInstancesRequest);
		// Return the Object Reference of the Instance just Launched
		Instance instance = runInstancesResult.getReservation().getInstances().get(0);

		// Add a Tag to the Instance
		CreateTagsRequest createTagsRequest = new CreateTagsRequest();
		createTagsRequest.withResources(instance.getInstanceId()).withTags(new Tag("Project", "2.2"));
		amazonEC2Client.createTags(createTagsRequest);

		try {
			Thread.sleep(60000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return instance;
	}

	public static String CreateELB(AmazonElasticLoadBalancingClient elb, AmazonEC2Client amazonEC2Client, String LG_DNS,
			String securityGroup) throws InterruptedException {
		// create load balancer
		CreateLoadBalancerRequest lbRequest = new CreateLoadBalancerRequest();
		lbRequest.setLoadBalancerName("loader");
		List<Listener> listeners = new ArrayList<Listener>(1);
		listeners.add(new Listener("HTTP", 80, 80));
		lbRequest.setListeners(listeners);
		lbRequest.withAvailabilityZones("us-east-1e").withSecurityGroups(securityGroup);
		CreateLoadBalancerResult lbResult = elb.createLoadBalancer(lbRequest);

		// Disable Connection Draining to avoid low speed when adding capacities
		ModifyLoadBalancerAttributesRequest LBdrainingrequest = new ModifyLoadBalancerAttributesRequest();
		LBdrainingrequest.setLoadBalancerName("loader");
		LoadBalancerAttributes LBdraining = new LoadBalancerAttributes();
		ConnectionDraining drainingcon = new ConnectionDraining();
		drainingcon.setEnabled(false);
		LBdraining.setConnectionDraining(drainingcon);
		LBdrainingrequest.setLoadBalancerAttributes(LBdraining);
		ModifyLoadBalancerAttributesResult LBdrainingresult = elb.modifyLoadBalancerAttributes(LBdrainingrequest);
		System.out.println("Disable Connection Draining successfully: "
				+ LBdrainingresult.getLoadBalancerAttributes().getConnectionDraining().getEnabled());

		// Add a Tag to the load balancer
		AddTagsRequest addTagsRequest = new AddTagsRequest();
		Collection<com.amazonaws.services.elasticloadbalancing.model.Tag> tag = new ArrayList<com.amazonaws.services.elasticloadbalancing.model.Tag>();
		com.amazonaws.services.elasticloadbalancing.model.Tag tagp2_2 = new com.amazonaws.services.elasticloadbalancing.model.Tag();
		tagp2_2.setKey("Project");
		tagp2_2.setValue("2.2");
		tag.add(tagp2_2);
		addTagsRequest.withLoadBalancerNames("loader").setTags(tag);
		elb.addTags(addTagsRequest);

		// Get ELB's DNS for later warm up
		Thread.sleep(5000);
		String ELB_DNS = lbResult.getDNSName();
		System.out.println("3.1 created load balancer successfully, its DNS is: " + ELB_DNS);

		// Set up health check page
		HealthCheck healthcheck = new HealthCheck();
		healthcheck.setTarget("HTTP:80/heartbeat?lg=" + LG_DNS);
		healthcheck.setTimeout(5);
		healthcheck.setInterval(30);
		healthcheck.setUnhealthyThreshold(2);
		healthcheck.setHealthyThreshold(10);

		ConfigureHealthCheckRequest HCrequest = new ConfigureHealthCheckRequest();
		HCrequest.setHealthCheck(healthcheck);
		HCrequest.setLoadBalancerName("loader");
		ConfigureHealthCheckResult HCresult = elb.configureHealthCheck(HCrequest);
		System.out.println("3.2 Set up health check page successfully: " + HCresult.getHealthCheck().getTarget());

		return ELB_DNS;
	}

	public static String getDNS(AmazonEC2Client amazonEC2Client, String InstanceId) {
		// Obtain a list of Reservations
		List<Reservation> reservations = amazonEC2Client.describeInstances().getReservations();
		for (Reservation reservation : reservations) {
			for (Instance instance : reservation.getInstances()) {
				if (instance.getState().getName().equals("running") & instance.getInstanceId().equals(InstanceId)) {
					return instance.getPublicDnsName();
				}
			}
		}
		return null;
	}

	public static CreateLaunchConfigurationRequest LaunchConfiguration(AmazonAutoScalingClient autoscalingGroup) {
		// Create a Launch Configuration
		CreateLaunchConfigurationRequest LCRequest = new CreateLaunchConfigurationRequest();
		LCRequest.setLaunchConfigurationName("launchConfiguration");
		LCRequest.setImageId("ami-3b2b515e");
		LCRequest.setInstanceType("m3.large");
		LCRequest.setKeyName("15619key");
		LCRequest.withSecurityGroups("Project2_2");
		// Set Detailed Monitoring: enabled
		InstanceMonitoring instanceMonitoring = new InstanceMonitoring();
		instanceMonitoring.setEnabled(true);
		LCRequest.setInstanceMonitoring(instanceMonitoring);
		try {
			Thread.sleep(30000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		// Check the Launch Configuration
		DescribeLaunchConfigurationsRequest DescribeLCRequest = new DescribeLaunchConfigurationsRequest();
		DescribeLCRequest.withLaunchConfigurationNames("launchConfiguration");
		DescribeLaunchConfigurationsResult DescribeLCResult = autoscalingGroup
				.describeLaunchConfigurations(DescribeLCRequest);
		System.out.println("4. Launch Configuraton successfully: " + DescribeLCResult.toString());
		return LCRequest;
	}

	public static List<String> CreateAutoScalingGroup(CreateLaunchConfigurationRequest LCRequest,
			AmazonAutoScalingClient autoscalingGroup) {
		// create an Auto Scaling Group
		CreateAutoScalingGroupRequest autoscalingrequest = new CreateAutoScalingGroupRequest();
		autoscalingrequest.setAutoScalingGroupName("autoScalingGroup");
		autoscalingrequest.setDesiredCapacity(2);
		autoscalingrequest.setMinSize(2);
		autoscalingrequest.setMaxSize(3);
		autoscalingrequest.withAvailabilityZones("us-east-1e");

		// add tags for the Auto Scaling Group
		Collection<com.amazonaws.services.autoscaling.model.Tag> tag = new ArrayList<com.amazonaws.services.autoscaling.model.Tag>();
		com.amazonaws.services.autoscaling.model.Tag tagp2_2 = new com.amazonaws.services.autoscaling.model.Tag();
		tagp2_2.setKey("Project");
		tagp2_2.setValue("2.2");
		tag.add(tagp2_2);
		autoscalingrequest.setTags(tag);

		// set advanced details for Auto Scaling Group
		autoscalingrequest.withLoadBalancerNames("loader");
		autoscalingrequest.setHealthCheckType("ELB");
		autoscalingrequest.setHealthCheckGracePeriod(119);

		// enable monitoring type
		autoscalingrequest.setLaunchConfigurationName(LCRequest.getLaunchConfigurationName());

		EnableMetricsCollectionRequest enableMetricsCollectionRequest = new EnableMetricsCollectionRequest();
		enableMetricsCollectionRequest.setAutoScalingGroupName("autoScalingGroup");
		enableMetricsCollectionRequest.setGranularity("1Minute");

		autoscalingGroup.createLaunchConfiguration(LCRequest);
		autoscalingGroup.createAutoScalingGroup(autoscalingrequest);
		autoscalingGroup.enableMetricsCollection(enableMetricsCollectionRequest);

		// check Auto Scaling Group
		DescribeAutoScalingGroupsRequest Describe_autoscalingGroupsRequest = new DescribeAutoScalingGroupsRequest();
		Describe_autoscalingGroupsRequest.withAutoScalingGroupNames("autoScalingGroup");
		DescribeAutoScalingGroupsResult Describe_autoscalingGroupsResult = autoscalingGroup
				.describeAutoScalingGroups(Describe_autoscalingGroupsRequest);
		System.out
				.println("5. Create Auto Scaling Groups successfully: " + Describe_autoscalingGroupsResult.toString());

		// Create Auto Scale out Policies
		PutScalingPolicyRequest policyRequestOut = new PutScalingPolicyRequest();
		policyRequestOut.setPolicyName("ScaleOutPolicy");
		policyRequestOut.setAutoScalingGroupName("autoScalingGroup");
		policyRequestOut.setAdjustmentType("ChangeInCapacity");
		policyRequestOut.setScalingAdjustment(1);
		policyRequestOut.setCooldown(120);
		PutScalingPolicyResult policyResultOut = autoscalingGroup.putScalingPolicy(policyRequestOut);
		String ScalingOutPolicyARN = policyResultOut.getPolicyARN();
		System.out.println("6.1 Scaling Out Policy " + policyResultOut.toString());

		// Create Auto Scale In policy
		PutScalingPolicyRequest policyRequestIn = new PutScalingPolicyRequest();
		policyRequestIn.setPolicyName("ScaleInPolicy");
		policyRequestIn.setAutoScalingGroupName("autoScalingGroup");
		policyRequestIn.setAdjustmentType("ChangeInCapacity");
		policyRequestIn.setScalingAdjustment(-1);
		policyRequestIn.setCooldown(120);
		PutScalingPolicyResult policyResultIn = autoscalingGroup.putScalingPolicy(policyRequestIn);
		String ScalingInPolicyARN = policyResultIn.getPolicyARN();
		System.out.println("6.2 Scaling In Policy " + policyResultIn.toString());

		List<String> policy = new ArrayList<String>();
		policy.add(ScalingOutPolicyARN);
		policy.add(ScalingInPolicyARN);
		return policy;
	}

	public static void cloudwatch(List<String> policy, AmazonCloudWatchClient cloudwatch) {
		String ScalingOutPolicyARN = policy.get(0);
		String ScalingInPolicyARN = policy.get(1);
		// Create a cloud watch Alarm invoking scale out policy
		PutMetricAlarmRequest alarmRequest_out = new PutMetricAlarmRequest();
		alarmRequest_out.setAlarmName("toohighCPUload");
		alarmRequest_out.setMetricName("CPUload");
		alarmRequest_out.setNamespace("AWS/EC2");
		alarmRequest_out.setStatistic("Average");
		alarmRequest_out.setPeriod(180);
		alarmRequest_out.setThreshold(80.00);
		alarmRequest_out.setComparisonOperator("GreaterThanThreshold");
		Dimension dimension = new Dimension();
		dimension.setName("AutoScalingGroupName");
		dimension.setValue("autoScalingGroup");
		alarmRequest_out.withDimensions(dimension);
		alarmRequest_out.setEvaluationPeriods(1);
		alarmRequest_out.withAlarmActions(ScalingOutPolicyARN);
		System.out.println(
				"7.1.1 Linked Scale out policy to cloudwatch Alarms successfully: " + alarmRequest_out.toString());

		// check scale out alarm
		cloudwatch.putMetricAlarm(alarmRequest_out);
		DescribeAlarmsRequest describe_AlarmsRequest_out = new DescribeAlarmsRequest();
		describe_AlarmsRequest_out.withAlarmNames("toohighCPUload");
		DescribeAlarmsResult describe_AlarmsResult_out = cloudwatch.describeAlarms(describe_AlarmsRequest_out);
		System.out.println("7.1.2 Check Alarm for too high CPU load:" + describe_AlarmsResult_out.toString());

		// Create a cloud watch Alarm invoking scale in policy
		PutMetricAlarmRequest alarmRequest_in = new PutMetricAlarmRequest();
		alarmRequest_in.setAlarmName("toolowCPUload");
		alarmRequest_in.setMetricName("CPUload");
		alarmRequest_in.setNamespace("AWS/EC2");
		alarmRequest_in.setStatistic("Average");
		alarmRequest_in.setPeriod(180);
		alarmRequest_in.setThreshold(20.00);
		alarmRequest_in.setComparisonOperator("LessThanThreshold");
		alarmRequest_in.withDimensions(dimension);
		alarmRequest_in.setEvaluationPeriods(1);
		alarmRequest_in.withAlarmActions(ScalingInPolicyARN);
		System.out.println(
				"7.2.1 Linked Scale out policy to cloudwatch Alarms successfully: " + alarmRequest_in.toString());

		// check scale in alarm
		cloudwatch.putMetricAlarm(alarmRequest_in);
		DescribeAlarmsRequest describe_AlarmsRequest_in = new DescribeAlarmsRequest();
		describe_AlarmsRequest_in.withAlarmNames("toolowCPUload");
		DescribeAlarmsResult describe_AlarmsResult_in = cloudwatch.describeAlarms(describe_AlarmsRequest_in);
		System.out.println("7.2.2 Check Alarm for too low CPU load:" + describe_AlarmsResult_in.toString());
	}

	public static void terminate() throws InterruptedException {
		// Terminate Auto Scaling Group
		UpdateAutoScalingGroupRequest update_asgRequest = new UpdateAutoScalingGroupRequest();
		update_asgRequest.withAutoScalingGroupName("autoScalingGroup").withMaxSize(0).withMinSize(0)
				.withDesiredCapacity(0);
		autoscalingGroup.updateAutoScalingGroup(update_asgRequest);
		System.out.println("Terminate Instances successfully");
		Thread.sleep(300000);

		DeleteAutoScalingGroupRequest delete_asgRequest = new DeleteAutoScalingGroupRequest();
		delete_asgRequest.withAutoScalingGroupName("autoScalingGroup");
		autoscalingGroup.deleteAutoScalingGroup(delete_asgRequest);
		System.out.println("Terminate Auto Scaling Group successfully");
		Thread.sleep(100000);

		// Terminate launch configuration
		DeleteLaunchConfigurationRequest delete_lcRequest = new DeleteLaunchConfigurationRequest();
		delete_lcRequest.setLaunchConfigurationName("launchConfiguration");
		autoscalingGroup.deleteLaunchConfiguration(delete_lcRequest);
		System.out.println("Terminate Launch Configuration successfully");

		// Terminate Auto Scale Policies
		DeletePolicyRequest delete_policyRequest = new DeletePolicyRequest();
		delete_policyRequest.withAutoScalingGroupName("autoScalingGroup");
		autoscalingGroup.deletePolicy(delete_policyRequest);
		System.out.println("Terminate Auto Scale Policies successfully");

		// Terminate Cloud Watch Alarms
		DeleteAlarmsRequest delete_AlarmsRequest_out = new DeleteAlarmsRequest();
		delete_AlarmsRequest_out.withAlarmNames("toohighCPUload");
		cloudwatch.deleteAlarms(delete_AlarmsRequest_out);
		System.out.println("Terminate Scale Out Cloud Watch Alarms successfully");

		DeleteAlarmsRequest delete_AlarmsRequest_in = new DeleteAlarmsRequest();
		delete_AlarmsRequest_in.withAlarmNames("toolowCPUload");
		cloudwatch.deleteAlarms(delete_AlarmsRequest_in);
		System.out.println("Terminate Scale In Cloud Watch Alarms successfully");

		// Terminate ELB
		DeleteLoadBalancerRequest delete_LBRequest = new DeleteLoadBalancerRequest();
		delete_LBRequest.withLoadBalancerName("loader");
		elb.deleteLoadBalancer(delete_LBRequest);
		System.out.println("Terminate Load Balancer successfully");

		// Terminate Security Group
		DeleteSecurityGroupRequest delete_SecurityGroupRequest = new DeleteSecurityGroupRequest();
		delete_SecurityGroupRequest.withGroupName("Project2_2");
		amazonEC2Client.deleteSecurityGroup(delete_SecurityGroupRequest);
		System.out.println("Terminate Security Group successfully");
	}

	public static void main(String[] args) throws MalformedURLException, IOException, InterruptedException {
		// Basic Credentials calling the Credentials.properties file
		Properties properties = new Properties();
		properties.load(Autoscaling.class.getResourceAsStream("/AwsCredentials.properties"));
		BasicAWSCredentials bawsc = new BasicAWSCredentials(properties.getProperty("accessKey"),
				properties.getProperty("secretKey"));

		// Create an Amazon EC2 Client
		AmazonEC2Client amazonEC2Client = new AmazonEC2Client(bawsc);
		// Create a security group
		String securitygroupid = CreateSecurity(amazonEC2Client, "Project2_2");

		// Create a Load Generator instance
		Instance LoadGenerator = CreateInstance(amazonEC2Client, "ami-312b5154", "m3.medium", "Projects");
		System.out.println("2.1 Launched an Instance with ID :" + LoadGenerator.getInstanceId());

		String LG_DNS = getDNS(amazonEC2Client, LoadGenerator.getInstanceId());
		System.out.println("2.2 The DNS of Load Generator is:" + LG_DNS);

		// Create an ELB, and return its DNS
		AmazonElasticLoadBalancingClient elb = new AmazonElasticLoadBalancingClient(bawsc);
		String ELB_DNS = CreateELB(elb, amazonEC2Client, LG_DNS, securitygroupid);

		// Create a Launch Configuration
		autoscalingGroup = new AmazonAutoScalingClient(bawsc);
		CreateLaunchConfigurationRequest LCRequest = LaunchConfiguration(autoscalingGroup);

		// Create an Auto Scaling Group
		List<String> policy = CreateAutoScalingGroup(LCRequest, autoscalingGroup);

		// Create an cloud watch client
		AmazonCloudWatchClient cloudwatch = new AmazonCloudWatchClient(bawsc);
		cloudwatch(policy, cloudwatch);

		// Enter submission password on Load Generator
		Thread.sleep(100000);
		URL url = new URL("http://" + LG_DNS + "/password?passwd=bFFR5T8Hw2VTczO7HnVhVm6WeKHWtN8f");
		HttpURLConnection urlcon = (HttpURLConnection) url.openConnection();
		urlcon.connect();
		Thread.sleep(50000);
		BufferedReader bufferRead = new BufferedReader(new InputStreamReader(urlcon.getInputStream()));
		while (bufferRead.readLine() == null) {
			urlcon = (HttpURLConnection) url.openConnection();
			urlcon.connect();
			bufferRead = new BufferedReader(new InputStreamReader(urlcon.getInputStream()));
		}
		System.out.println("10. Connect Load Generator successfully");

		// Warm up ELB 5 times
		Thread.sleep(50000);
		for (int i = 0; i < 5; i++) {
			boolean flag = true;
			String warmup_log = "";
			while (flag) {
				try {
					String userResponse = "";
					URL url_warmup = new URL("http://" + LG_DNS + "/warmup?dns=" + ELB_DNS);
					HttpURLConnection urlcon_warmup = (HttpURLConnection) url_warmup.openConnection();
					urlcon_warmup.connect();
					Thread.sleep(100000);
					BufferedReader bufferRead_warmup = new BufferedReader(
							new InputStreamReader(urlcon_warmup.getInputStream()));
					while ((userResponse = bufferRead_warmup.readLine()) != null)
						warmup_log += userResponse;
					// if warm up successfully, the log won't show invalid DNS,
					// otherwise, try warm up once again
					if (!warmup_log.contains("Invalid")) {
						Thread.sleep(960000);
						bufferRead_warmup.close();
						flag = false;
					}
					System.out.println("11. Warm up succeefully:" + warmup_log);
				} catch (StringIndexOutOfBoundsException e) {
					// e.printStackTrace();
				} catch (IOException e) {
					// e.printStackTrace();
				} catch (InterruptedException e) {
					// e.printStackTrace();
				}
			}
		}

		// Start test, and get its testId
		String testid = "";
		String testResponse = "";
		URL url_junior = new URL("http://" + LG_DNS + "/junior?dns=" + ELB_DNS);
		HttpURLConnection urlcon_junior = (HttpURLConnection) url_junior.openConnection();
		urlcon_junior.connect();
		Thread.sleep(30000);
		BufferedReader bufferRead_junior = new BufferedReader(new InputStreamReader(urlcon_junior.getInputStream()));
		while ((testResponse = bufferRead_junior.readLine()) == null) {
			urlcon = (HttpURLConnection) url_junior.openConnection();
			urlcon_junior.connect();
			bufferRead = new BufferedReader(new InputStreamReader(urlcon_junior.getInputStream()));
		}
		String[] retval = testResponse.split("\\.");
		testid = retval[1];
		System.out.println("12. Start test successfully, its testid is " + testid);
		bufferRead_junior.close();

		// run test for 48 minutes
		Thread.sleep(2880000);
		
		// Terminate all sources
		terminate();
	}
}
