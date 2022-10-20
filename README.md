# UnhealthyStateRuleSentinel
This Repository provides detection rule when Recommendation of Microsoft Defender for Cloud state was changed to "Unhealthy".

# How to import
You can select import button from Microsoft Sentinel.
Caution: 
 - Requires "Recommendation" table in the target LogAnalytics workspace.
 - That means, previously you need to configure "Continuous Export" from Microsoft Defender for Cloud to the Sentinel LA Workspace.

<img width="774" alt="image" src="https://user-images.githubusercontent.com/55295601/196851071-0f1ee2ad-2aac-4e12-84fb-ababd27d73da.png">

# Current KQL Query.
Current version, here is a Kusto Query in this package.

```
let queryfrequency = 1h;
SecurityRecommendation
| where TimeGenerated > ago(queryfrequency)
| where RecommendationState == "Unhealthy"
| where IsSnapshot == "false" // For Continuous Export without Snapshot
| where Environment == "Azure" //For Azure
| extend
    FirstEvaluationDate = tostring(Properties.status.firstEvaluationDate),
    StatusChangeDate = tostring(Properties.status.statusChangeDate)
| extend SubscriptionId = split(AssessedResourceId, "/",2)[0], ResouceGroup = split(AssessedResourceId, "/",4)[0]
| project TimeGenerated,RecommendationName,RecommendationSeverity,FirstEvaluationDate,StatusChangeDate,AssessedResourceId,SubscriptionId,ResouceGroup
```

If you want to monitor multi-cloud environment, comment out '| where Environment == "Azure"'.

# CurrentParameter
Here is a current parameter on this package.

|  Parameter  |  Value  | Description |
| ---- | ---- | ---- |
|  queryfrequency  |  1h  | |
| RecommendationName | | Recommendation Name from Microsoft Defender for Cloud |
| RecommendationSeverity | High/Middle/Low | Recommendation Severity |
| FirstEvaluationDate |  | First Evaluation Date by Azure Policy |
| StatusChangeDate |  | Status Change Date by Azure Policy |

