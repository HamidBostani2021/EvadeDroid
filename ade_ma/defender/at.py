"""
The script is for Adversarial training incorporating attacks such as pgdl1, pgdl2, pgdlinf, pgdadam
"""

import os
import sys
from datetime import datetime
from timeit import default_timer
import warnings

#Hamid import tensorflow as tf
import tensorflow.compat.v1 as tf
tf.disable_v2_behavior()

import numpy as np
from sklearn.metrics import f1_score

proj_dir = os.path.dirname(os.path.dirname(__file__))
sys.path.append(proj_dir)

from config import config
from tools import utils
from learner.basic_DNN import BasicDNNModel, feature_type_scope_dict, graph, INFO, DNN_HP
from attacker.methods.pgd_adam import PGDAdam
from attacker.methods.pgdl1 import PGDl1
from attacker.methods.pgd import PGD
from attacker.feature_reverser import DrebinFeatureReverse

# generative methods
MAXIMIZER_METHOD_DICT = {
    'pgd_adam': PGDAdam,
    'pgd_l1': PGDl1,
    'pgd_l2': PGD,
    'pgd_inf': PGD
}

# the corresponding default hyper-parameters
MAXIMIZER_PARAM_DICT = {
    'pgd_adam': {'learning_rate': 0.02, 'max_iteration': 100, 'batch_size': 128},
    'pgd_l1': {'k': 1, 'step_size': 1., 'max_iteration': 50, 'batch_size': 128, 'force_iteration': False},
    'pgd_l2': {'step_size': 1., 'ord': 'l2', 'max_iteration': 100, 'rand_round': False, 'batch_size': 128},
    'pgd_inf': {'step_size': 0.01, 'ord': 'l-infinity', 'max_iteration': 100, 'rand_round': True, 'batch_size': 128}
}

ADV_TRAIN_HP = {
    'maximizer_name': 'pgd_adam',  # ['pgd_adam', 'pgd_inf']
    'trials': 0,  # for random point start, trials is a non-negative integer, i.e., trials >= 0
    'eta': 0.001,  # degree of random perturbations for random points: input_dim * eta
    'lambda_': 0.5  # balance factor for training on pristine data and adversarial one
}


class AdversarialTrainingDNN(BasicDNNModel):
    def __init__(self,
                 info_dict=None,
                 hyper_params=None,
                 reuse=False,
                 is_saving=True,
                 init_graph=True,
                 mode='train',
                 name='ADV_TRAINING_DNN'):
        """
        hardened model incorporated with adversarial training
        @param info_dict: None,
        @param hyper_params: hyper parameters,
        @param reuse: reuse the variables or not
        @param is_saving: option for saving weights
        @param init_graph: initialize graph
        @param mode: enable a mode for run the model, 'train' or 'test'
        @param name: model name
        """
        self.is_saving = is_saving
        self.init_graph = init_graph
        self.mode = mode
        if info_dict is None:
            info_dict = INFO
        # get useful information, this will be over-wrote in other class
        self.info = utils.ParamWrapper(info_dict)
        self.feature_tp = self.info.feature_type

        if hyper_params is None:
            ADV_TRAIN_HP.update(DNN_HP)
            hyper_params = ADV_TRAIN_HP # hyper_params contains information of using which attack
        self.hp_params = utils.ParamWrapper(hyper_params)

        # initialization
        #if self.feature_tp == feature_type_scope_dict.keys()[0]:
        if self.feature_tp == [*feature_type_scope_dict.keys()][0]:
            self.normalizer = utils.read_pickle(config.get('feature.' + self.feature_tp, 'normalizer'))
        else:
            raise ValueError("Feature type is incompatible.")
        input_dim = len(utils.read_pickle(config.get('feature.' + self.feature_tp, 'vocabulary')))
        self.eta = self.hp_params.eta
        feature_reverser = DrebinFeatureReverse()
        allow_insert_array, allow_removal_array = feature_reverser.get_mod_array()

        inner_max_name = self.hp_params.maximizer_name
        inner_max_param = MAXIMIZER_PARAM_DICT[inner_max_name]
        self.inner_maximizer = MAXIMIZER_METHOD_DICT[inner_max_name](self,
                                                                     input_dim,
                                                                     allow_insert_array,
                                                                     allow_removal_array,
                                                                     self.normalizer,
                                                                     verbose=False,
                                                                     **inner_max_param
                                                                     )

        self.batch_size_mal = tf.Variable(0, dtype=tf.int64, trainable=False)
        super(AdversarialTrainingDNN, self).__init__(info_dict,
                                                     hyper_params,
                                                     reuse,
                                                     self.is_saving,
                                                     self.init_graph,
                                                     self.mode,
                                                     name + '_' + inner_max_name.upper()
                                                     )

    def forward(self, x_tensor, y_tensor, reuse=False):
        # graph
        self.nn = graph
        _1, _2, _3 = graph(
            x_tensor, self.hidden_layers, self.output_dim,
            is_training=False, name=self.model_name, reuse=reuse
        )
        if self.mode == 'train':
            adv_x, rtn_x, rtn_y = self.gen_adv_mal_graph(x_tensor, y_tensor, self.hp_params.trials)

            self.adv_x = tf.cond(self.is_training,
                                 lambda: tf.concat([x_tensor, adv_x], axis=0),
                                 lambda: x_tensor)
            self.adv_y = tf.cond(self.is_training,
                                 lambda: tf.concat([y_tensor, rtn_y], axis=0),
                                 lambda: y_tensor)

        elif self.mode == 'test':
            self.adv_x = x_tensor
            self.adv_y = y_tensor
        else:
            pass

        _1, _2, logits = graph(
            self.adv_x, self.hidden_layers, self.output_dim,
            is_training=self.is_training, name=self.model_name, reuse=True
        )
        y_tensor = self.adv_y

        return logits, y_tensor

    def model_inference(self):
        # loss definition
        cross_entropy_orig = tf.losses.sparse_softmax_cross_entropy(
            labels=self.y_tensor[:self.hp_params.batch_size],
            logits=self.logits[:self.hp_params.batch_size]
        )
        cross_entropy_aug = tf.losses.sparse_softmax_cross_entropy(
            labels=self.y_tensor[self.hp_params.batch_size:],
            logits=self.logits[self.hp_params.batch_size:]
        )
        self.cross_entropy = self.hp_params.lambda_ * cross_entropy_aug + \
                             (1. - self.hp_params.lambda_) * cross_entropy_orig
        self.y_xent = tf.nn.sparse_softmax_cross_entropy_with_logits(
            labels=self.y_tensor,
            logits=self.logits
        )

        # prediction
        self.y_proba = tf.nn.softmax(self.logits)
        self.y_pred = tf.argmax(self.logits, axis=1)

        # some information
        self.accuracy = tf.reduce_mean(
            tf.to_float(tf.equal(self.y_pred, self.y_tensor))
        )

    def gen_adv_mal_graph(self, x_tensor, y_tensor, trials=0):
        """
        static graph for enhancing attack
        :param x_tensor: batch of input data
        :param y_tensor: batch of ground truths
        :param trials: number of trials
        :return: the strongest attack
        """
        mal_indices = tf.where(y_tensor)  # '1' denotes the malicious sample
        mal_x_tensor = tf.gather_nd(x_tensor, mal_indices)
        mal_y_tensor = tf.gather_nd(y_tensor, mal_indices)

        ben_indices = tf.where(tf.equal(y_tensor, 0))
        ben_x_tensor = tf.gather_nd(x_tensor, ben_indices)
        ben_y_tensor = tf.gather_nd(y_tensor, ben_indices)
        with tf.control_dependencies([mal_x_tensor, mal_y_tensor]):
            self.batch_size_mal = tf.assign(self.batch_size_mal, tf.reduce_sum(y_tensor))

        def filter(adv_mal_x):
            """
            replace the perturbed case but not adversarial case of pristine data
            """
            _1, _2, logits = self.nn(adv_mal_x,
                                     self.hidden_layers,
                                     self.output_dim,
                                     False,
                                     name=self.model_name,
                                     reuse=True)
            pred_y_adv = tf.argmax(logits, axis=1)
            incorrect_case = tf.reshape(tf.to_float(tf.logical_not(
                tf.equal(pred_y_adv, mal_y_tensor))), (-1, 1))
            return tf.stop_gradient((adv_mal_x - mal_x_tensor) * incorrect_case + mal_x_tensor)

        if trials == 0:
            adv_mal_x = filter(
                tf.stop_gradient(self.inner_maximizer.graph(mal_x_tensor, mal_y_tensor))
            )

            adv_x_tensor = tf.concat([adv_mal_x, ben_x_tensor], axis=0)
            rtn_x = tf.concat([mal_x_tensor, ben_x_tensor], axis=0)
            rtn_y = tf.concat([mal_y_tensor, ben_y_tensor], axis=0)
            return adv_x_tensor, rtn_x, rtn_y
        elif trials >= 1: # random start
            x_shape = mal_x_tensor.get_shape().as_list()
            mal_x_batch_ext = tf.tile(mal_x_tensor, [trials, 1])
            mal_y_batch_ext = tf.tile(mal_y_tensor, [trials, ])

            eta = tf.random_uniform([1, ], 0, self.hp_params.eta)
            init_perturbations = tf.random_uniform(tf.shape(mal_x_batch_ext),
                                                   minval=-1.,
                                                   maxval=1.,
                                                   dtype=tf.float32)
            init_perturbations = tf.multiply(
                tf.sign(init_perturbations),
                tf.to_float(
                    tf.abs(init_perturbations) > 1. - eta),
            )

            init_x_batch_ext = self.inner_maximizer.project_perturbations(
                mal_x_batch_ext,
                init_perturbations
            )

            adv_x_batch_ext = tf.stop_gradient(
                self.inner_maximizer.graph(
                    init_x_batch_ext,
                    mal_y_batch_ext
                ))

            def _loss_fn(x, y):
                _1, _2, logits = self.nn(x, self.hidden_layers, self.output_dim, False, name=self.model_name,
                                         reuse=True)
                return -1 * tf.nn.sparse_softmax_cross_entropy_with_logits(logits=logits,
                                                                           labels=y)

            adv_losses = _loss_fn(adv_x_batch_ext, mal_y_batch_ext)

            adv_x_pool = tf.reshape(adv_x_batch_ext, [trials, -1, x_shape[1]])
            adv_losses = tf.reshape(adv_losses, [trials, -1])

            idx_selected = tf.stack([tf.argmin(adv_losses, axis=0),
                                     tf.range(self.batch_size_mal, dtype=tf.int64)], axis=1)

            adv_mal_x = filter(tf.gather_nd(adv_x_pool, idx_selected))

            adv_x_tensor = tf.concat([adv_mal_x, ben_x_tensor], axis=0)
            rtn_x = tf.concat([mal_x_tensor, ben_x_tensor], axis=0)
            rtn_y = tf.concat([mal_y_tensor, ben_y_tensor], axis=0)
            return adv_x_tensor, rtn_x, rtn_y

        else:
            raise ValueError("trials shall be a non-negative integer.")

    def train(self, trainX=None, trainy=None, valX=None, valy=None):
        """train dnn"""
        if trainX is None or trainy is None or valX is None or valy is None:
            trainX, valX, _ = utils.read_joblib(config.get('feature.' + self.feature_tp, 'dataX'))
            trainy, valy, _ = utils.read_joblib(config.get('feature.' + self.feature_tp, 'datay'))

        train_input = utils.DataProducer(trainX, trainy,self.hp_params.batch_size, n_epochs=self.hp_params.n_epochs)
        val_input = utils.DataProducer(valX, valy, self.hp_params.batch_size, name='val')

        # perturb the malware representations
        val_mal_indicator = (valy == 1.)
        val_malX = valX[val_mal_indicator]
        val_maly = valy[val_mal_indicator]

        # attack initilization
        self.inner_maximizer.init_graph()

        global_train_step = tf.train.get_or_create_global_step()
        saver = tf.train.Saver()
        tf.summary.scalar('accuracy_adv_train', self.accuracy)
        tf.summary.scalar('loss_adv_train', self.cross_entropy)
        merged_summaries = tf.summary.merge_all()

        # optimizer
        with tf.control_dependencies(tf.get_collection(tf.GraphKeys.UPDATE_OPS)):
            optimizer = tf.train.AdamOptimizer(self.hp_params.learning_rate).minimize(self.cross_entropy,
                                                                                      global_step=global_train_step)
        tf_cfg = tf.ConfigProto(log_device_placement=True, allow_soft_placement=True)
        tf_cfg.gpu_options.allow_growth = True
        tf_cfg.gpu_options.per_process_gpu_memory_fraction = 1.0
        sess = tf.Session(config=tf_cfg)

        with sess.as_default():
            summary_writer = tf.summary.FileWriter(self.save_dir, sess.graph)
            sess.run(tf.global_variables_initializer())

            training_time = 0.0
            train_input.reset_cursor()
            output_steps = 500
            best_avg_score_val = 0.
            for step_idx, X_batch, y_batch in train_input.next_batch():
                train_dict = {
                    self.x_input: X_batch,
                    self.y_input: y_batch,
                    self.is_training: True
                }

                if (step_idx + 1) % output_steps == 0:
                    print('Step {}/{}:{}'.format(step_idx + 1, train_input.steps, datetime.now()))
                    val_input.reset_cursor()
                    val_res_list = [sess.run([self.accuracy, self.y_pred], feed_dict={self.x_input: valX_batch,
                                                                                      self.y_input: valy_batch,
                                                                                      self.is_training: False}) \
                                    for [_, valX_batch, valy_batch] in val_input.next_batch()
                                    ]
                    val_res = np.array(val_res_list, dtype=object)
                    _acc = np.mean(val_res[:, 0])
                    _pred_y = np.concatenate(val_res[:, 1])
                    from sklearn.metrics import f1_score
                    _f1_score = f1_score(valy, _pred_y[:valy.shape[0]])

                    _, _adv_valX, _ = self.inner_maximizer.perturb(val_malX, val_maly, sess)
                    _adv_acc_val = sess.run(self.accuracy, feed_dict={self.x_input: _adv_valX,
                                                                      self.y_input: val_maly,
                                                                      self.is_training: False})
                    _avg_score = (_f1_score + _adv_acc_val) / 2.
                    print('    validation accuracy {:.5}%'.format(_acc * 100))
                    print('    validation f1 score {:.5}%'.format(_f1_score * 100))
                    print('    validation accuracy on adversarial malware samples {:.5}%'.format(_adv_acc_val * 100))

                    if step_idx != 0:
                        print('    {} samples per second'.format(
                            output_steps * self.hp_params.batch_size / training_time))
                        training_time = 0.

                    summary = sess.run(merged_summaries, feed_dict=train_dict)
                    summary_writer.add_summary(summary, global_train_step.eval(sess))

                    if best_avg_score_val <= _avg_score:
                        best_avg_score_val = _avg_score
                        if not os.path.exists(self.save_dir):
                            os.makedirs(self.save_dir)
                        saver.save(sess, os.path.join(self.save_dir, 'checkpoint'),
                                   global_step=global_train_step)

                start = default_timer()
                sess.run(optimizer, feed_dict=train_dict)
                end = default_timer()
                training_time = training_time + end - start
        sess.close()


def _main():
    adv_train_dnn = AdversarialTrainingDNN()
    adv_train_dnn.train()
    adv_train_dnn.mode = 'test'
    adv_train_dnn.test_rpst()


if __name__ == "__main__":
    _main()