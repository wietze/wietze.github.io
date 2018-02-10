
$.getJSON( "https://www.helpdeskweb.nl/partners/wietze/tweet.php?ts="+ Math.round(+new Date()/1000), function( data ) {
//<?PHP echo $tweet.' <a href="http://www.twitter.com/wietze/status/'.$tweets[0]['id'].'/" style="color: #aaa; font-size: 12px; margin-left: 10px;">'.timeAgo($tweets[0]['created_at']).'</a>'; ?>

  contents = data['tweet'] + ' <a href="http://www.twitter.com/wietze/status/' + data['id'] + '/" style="color: #aaa; font-size: 12px; margin-left: 10px;">' + data['time'] + '</a>';
  $('#twit').append(contents);
});

