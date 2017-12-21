# This is what I used to delete old votes once. I hope to one day include it in
# a script, like in delete-expired.py
# Or even better, to not need it because votes properly cascade from items
delete from vote where (vote_type ="post-passes" or vote_type = "post-quality") and not exists ( select post_id from post where post.post_id = vote.item_on_id );
