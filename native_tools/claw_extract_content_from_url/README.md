# claw_extract_content_from_url

This skill provides an automated way to extract raw content from a given internet URL. 
The url can point to html pages, pdf files, doc files but also Youtube videos.
It interfaces with the `ParseJet` extraction API to process pages and return structured or unstructured text content.

## Parameters

* `url` (string, required): The target internet URL to scrape and extract content from.

## Output Structure

The output is returned as standard JSON enclosing the response retrieved from the ParseJet service.

```json
{
  "result": {
    // ParseJet response payload
  },
  "skill": "claw_extract_content_from_url",
  "action_id": "<action_id>"
}
```

## Example Usage

Input arguments (`SKILL_ARGS` environment variable):

```json
{
  "url": "https://example.com/article"
}
```
