
$.getJSON( "https://www.helpdeskweb.nl/partners/wietze/tweet.php?www&ts="+ Math.round(+new Date()/1000), function( data ) {
  contents = data['tweet'] + ' <a href="https://www.twitter.com/wietze/status/' + data['id'] + '" style="color: #aaa; font-size: 12px; margin-left: 10px;">' + data['time'] + '</a>';
  $('#twit').append(contents);
});

