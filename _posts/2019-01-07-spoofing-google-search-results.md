---
layout: post
title: Spoofing Google Search results
tldr: By adding two parameters to any Google Search URL, you can replace search results with a Knowledge Graph card of your choice. A malicious user can use this to generate false information or 'fake news'.
image: /assets/2019-01-07-knowledge-graph-2.jpg
tags: [google, google search, fake news, misinformation, knowledge graph, knowledge card, google bug, google spoof, spoofing]
---

 ***Update*** -
 *Two days after the publication of this blog post, Google [seems to have fixed](https://twitter.com/Wietze/status/1083658736248541184) the issue, after TechCrunch [asked the firm](https://techcrunch.com/2019/01/09/a-simple-bug-makes-it-easy-to-spoof-google-search-results-into-spreading-misinformation/) whether it was planning on taking any action. Although no official announcement was made, it looks like the* `kgmid` *parameter has been disabled. As a result, the flaw described below is no longer working.*

----

## Knowledge Graph
A few years ago, when you entered a search query into Google Search , you would simply get a list of search results. When you do the same now, you get all sorts of extra information supplied by Google. For instance, if you search for 'UNICEF', you'll see a box next to the search results with some key facts about this organisation. This feature is called Knowledge Graph.

Google brought Knowledge Graph to its search engine in 2012 as a means to *instantly get information that’s relevant to your query* [[1]]. Whilst the information often comes straight from Wikipedia, this is not always the case - unfortunately Knowledge Graph doesn't tell you where it got the information from. In addition, the algorithm sometimes mixes up information when there are multiple matches (e.g. people with the same name). This has lead to a small number of incidents regarding the feature's accuracy [[2], [3]].

More features were introduced afterwards, such as Featured Snippets [[4]] and built-in answers (such as '*what is my ip address*', '*what time is it in Bejing*', '*how many ounces in a gallon*', etc.). Although these features are not part of Knowledge Graph, they work in a similar fashion. As a result of all these features, users can ask Google Search questions and get an answer straight away, without leaving the search engine.

A side effect of all this is that people have effectively been trained to take information from these boxes that appear when googling. It's convenient and quick - I have caught myself relying on the information presented by Google rather than studying the search results, and I'm sure you have too.

[![Screenshot of a Google Search with a Knowledge Graph card on the right.](/assets/2019-01-07-knowledge-graph-1.jpg)](/assets/2019-01-07-knowledge-graph-1.jpg)
*Example of a Google Search with a Knowledge Graph card on the right*

## Search queries and Knowledge Graph cards
A closer examination of Knowledge Graph shows that you can attach a Knowledge Graph card to your Google Search, which might be helpful if you want to share information provided in a Knowledge Graph card with someone else.

If you click on the share button - present on every card - you'll be given a shortened link (a `https://g.co/` address). Following this link will redirect you back to `google.com` with the original search query. What's different however are the parameters used: the URL will contain a `&kgmid` parameter. The value of this parameter is the unique identifier of the Knowledge Graph card shown on the page.

As it turns out, you can add this parameter to any valid Google Search URL, and it will show you the Knowledge Graph card next to the search results of the search query. For instance, you can add the Knowledge Graph card of Paul McCartney (`kgmid=/m/03j24kf`) to a search for the [Beatles](https://www.google.com/search?q=The+Beatles&kgmid=/m/03j24kf), even though that card would normally not appear for that query.

While this can be helpful, this also means you can link up different pieces of information and give the impression they are related. Adding Paul McCartney's Knowledge Graph card to a search query for the [Rolling Stones](https://www.google.com/search?q=Rolling+Stones&kgmid=/m/03j24kf) doesn't make much sense, but if I give this link to my friend who doesn't know much about music, she might think McCartney was a member of the Rolling Stones. By looking at the search results however, it's easy to find out this is not the case.

Google also offers a way to view the Knowledge Graph card in isolation and omit the search results. This can be done by adding the `&kponly` parameter to the URL: the Knowledge Graph card is no longer a side panel, but has moved to where you would normally see the search results. Strangely enough, the search bar is still visible with the original query, even though no search results are shown at all. [This link](https://www.google.com/search?q=Rolling+Stones&kgmid=/m/03j24kf&kponly) only shows Paul McCartney's card, but the query (still embedded in the URL) is still visible, even though it now has no relevance whatsoever with what is shown.

## 'Spoofing' a search result
These two things combined open the door to abuse: if, for example, your search query is a question, you can now pick a Knowledge Graph card that has your desired answer and *only* show this desired answer. Forward on the link to someone else and you might convince them [Jaffa cakes are actually biscuits](https://www.google.com/search?q=Are+Jaffa+cakes+biscuits+or+cakes&kgmid=/m/01tqs1&kponly). More seriously, this technique could be used for spreading false information for political or ideological gain.

Examples include:
- [What party should I vote for?](https://www.google.com/search?q=What+party+should+I+vote+for&kgmid=/m/01c9x&kponly)
- [Who is responsible for 9/11?](https://www.google.com/search?q=Who+is+responsible+for+9%2f11&kgmid=/m/09b6zr&kponly)
- [By whom was Donald Trump endorsed?](https://www.google.com/search?q=By+whom+was+Donald+Trump+endorsed&kgmid=/m/05ngt2&kponly)
- [Where was Barack Obama born?](https://www.google.com/search?q=Where+was+Barack+Obama+born&kgmid=/m/019rg5&kponly)

(To make it absolutely clear, the answer in the first link is subjective and the the last three answers are factually incorrect.)

[![Screenshot of a Google Search which seems to suggests George W. Bush was responsible for the 9/11 terrorist attack.](/assets/2019-01-07-knowledge-graph-2.jpg)](/assets/2019-01-07-knowledge-graph-2.jpg)
*An example of how easy it is to produce fake news using Google Search.*

The point is that this allows you to trick others into believing something is true. After all, it is a legitimate Google Search link and since we have been trained to trust the answers provided by Google, there must be some truth in it, right?

To prevent people from abusing Knowledge Graph, the disabling of the `kponly` parameter by Google would definitely help (when would you ever *just* want to see a card without further context?), although in my opinion removing the `kgmid` option altogether would be even better.


This issue isn't completely new - I found out about this over a year ago and even then I wasn't the only one aware of it. What is surprising though is that the problem still hasn't been addressed by Google. The bug report I filed about a year ago was closed as it wasn't considered a severe enough vulnerability. I disagree: in this day and age of fake news and alternative facts, it is irresponsible to have a 'feature' that allows people to fabricate false information on a platform trusted by many.

Don't be evil. Or as per Alphabet's new motto: do the right thing.

[1]: https://googleblog.blogspot.com/2012/05/introducing-knowledge-graph-things-not.html
[2]: https://www.nytimes.com/2017/12/16/business/google-thinks-im-dead.html
[3]: https://www.theregister.co.uk/2015/12/08/wikidata_special_report/
[4]: https://www.blog.google/products/search/reintroduction-googles-featured-snippets/
[5]: https://plus.google.com/+AaronBradley/posts/92wjiusi2YC
