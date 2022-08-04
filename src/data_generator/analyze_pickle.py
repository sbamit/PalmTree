import pickle
import re

ground_truth_file = "mapping-NO-filter.pkl"

with open(ground_truth_file, 'rb') as f:
    ground_truth_bb_pairs = pickle.load(f)

#What is the maximum number of tokens?
max_num_of_tokens = 0
avg_num_of_tokens = 0
sum = 0; count = 0
#Check out the dataset
for key, text in ground_truth_bb_pairs.items():
  print(key,'\t',text[0])
  if(len(text)>1):
    print('\t\t',text[1])
  no_of_tokens = len(re.split(' +|;',text[0])) - 1
  if(max_num_of_tokens< no_of_tokens):
    max_num_of_tokens = no_of_tokens
  sum += no_of_tokens
  count += 1 

avg_num_of_tokens = sum//count
print('# of items in \'ground_truth_bb_pairs\':', len(ground_truth_bb_pairs))
#Show maximum and average number of tokens
print('MAX number of tokens in a basic block:', max_num_of_tokens)
print('AVG number of tokens in a basic block', avg_num_of_tokens)